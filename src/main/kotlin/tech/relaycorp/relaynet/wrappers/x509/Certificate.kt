package tech.relaycorp.relaynet.wrappers.x509

import org.bouncycastle.asn1.DERBMPString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.dateToZonedDateTime
import tech.relaycorp.relaynet.getSHA256Digest
import tech.relaycorp.relaynet.getSHA256DigestHex
import tech.relaycorp.relaynet.wrappers.generateRandomBigInteger
import java.io.IOException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathBuilderResult
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.sql.Date
import java.time.ZonedDateTime

/**
 * Relaynet PKI Certificate.
 *
 * @param certificateHolder Bouncy Castle representation of the X.509 certificate
 */
class Certificate constructor(val certificateHolder: X509CertificateHolder) {
    companion object {
        private val bcToJavaCertificateConverter: JcaX509CertificateConverter =
            JcaX509CertificateConverter().setProvider(BC_PROVIDER)

        /**
         * Issue a new Relaynet PKI certificate.
         *
         * @suppress
         */
        @Throws(CertificateException::class)
        internal fun issue(
            subjectCommonName: String,
            subjectPublicKey: PublicKey,
            issuerPrivateKey: PrivateKey,
            validityEndDate: ZonedDateTime,
            issuerCertificate: Certificate? = null,
            isCA: Boolean = false,
            pathLenConstraint: Int = 0,
            validityStartDate: ZonedDateTime = ZonedDateTime.now()
        ): Certificate {
            if (validityStartDate >= validityEndDate) {
                throw CertificateException("The end date must be later than the start date")
            }
            if (issuerCertificate != null) {
                requireCertificateToBeCA(issuerCertificate)
            }

            val subjectDistinguishedName = buildDistinguishedName(subjectCommonName)
            val issuerDistinguishedName = if (issuerCertificate != null)
                issuerCertificate.certificateHolder.subject
            else
                subjectDistinguishedName
            val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.encoded)
            val builder = X509v3CertificateBuilder(
                issuerDistinguishedName,
                generateRandomBigInteger(),
                Date.from(validityStartDate.toInstant()),
                Date.from(validityEndDate.toInstant()),
                subjectDistinguishedName,
                subjectPublicKeyInfo
            )

            val basicConstraints = BasicConstraintsExtension(isCA, pathLenConstraint)
            builder.addExtension(Extension.basicConstraints, true, basicConstraints)

            val subjectPublicKeyDigest = getSHA256Digest(subjectPublicKeyInfo.encoded)
            val subjectSKI = SubjectKeyIdentifier(subjectPublicKeyDigest)
            builder.addExtension(Extension.subjectKeyIdentifier, false, subjectSKI)

            var issuerSKI = subjectSKI
            if (issuerCertificate != null) {
                issuerSKI =
                    SubjectKeyIdentifier.fromExtensions(
                        issuerCertificate.certificateHolder.extensions
                    ) ?: throw CertificateException(
                        "Issuer must have the SubjectKeyIdentifier extension"
                    )
            }
            val aki = AuthorityKeyIdentifier(issuerSKI.keyIdentifier)
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki)

            val signer = JcaContentSignerBuilder("SHA256WITHRSAANDMGF1")
                .setProvider(BC_PROVIDER)
                .build(issuerPrivateKey)
            return Certificate(builder.build(signer))
        }

        @Throws(CertificateException::class)
        private fun buildDistinguishedName(commonName: String): X500Name {
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.CN, DERBMPString(commonName))
            return builder.build()
        }

        private fun requireCertificateToBeCA(issuerCertificate: Certificate) {
            val issuerBasicConstraintsExtension =
                issuerCertificate.certificateHolder.getExtension(Extension.basicConstraints)
                    ?: throw CertificateException(
                        "Issuer certificate should have basic constraints extension"
                    )
            val issuerBasicConstraints =
                BasicConstraints.getInstance(issuerBasicConstraintsExtension.parsedValue)
            if (!issuerBasicConstraints.isCA) {
                throw CertificateException("Issuer certificate should be marked as CA")
            }
        }

        /**
         * Deserialize certificate,
         *
         * @param certificateSerialized The DER-encoded serialization of the certificate
         */
        @Throws(CertificateException::class)
        fun deserialize(certificateSerialized: ByteArray): Certificate {
            val certificateHolder = try {
                X509CertificateHolder(certificateSerialized)
            } catch (_: IOException) {
                throw CertificateException(
                    "Value should be a DER-encoded, X.509 v3 certificate"
                )
            }
            return Certificate(certificateHolder)
        }
    }

    /**
     * Return the Common Name of the subject
     */
    val commonName: String
        get() {
            val commonNames = certificateHolder.subject.getRDNs(BCStyle.CN)
            return commonNames.first().first.value.toString()
        }

    /**
     * Calculate the private address of the subject
     */
    val subjectPrivateAddress
        get() = "0" + getSHA256DigestHex(certificateHolder.subjectPublicKeyInfo.encoded)

    /**
     * Report whether this certificate equals another.
     */
    override fun equals(other: Any?): Boolean {
        if (other !is Certificate) {
            return false
        }
        return certificateHolder == other.certificateHolder
    }

    /**
     * Return the hash code of the certificate.
     */
    override fun hashCode(): Int {
        return certificateHolder.hashCode()
    }

    /**
     * Return the DER cerialization of the certificate.
     */
    fun serialize(): ByteArray {
        return certificateHolder.encoded
    }

    /**
     * Validate the certificate.
     *
     * @throws CertificateException If the certificate is invalid
     */
    @Throws(CertificateException::class)
    fun validate() {
        validateValidityPeriod()
        validateCommonNamePresence()
    }

    private fun validateValidityPeriod() {
        val now = ZonedDateTime.now()
        if (now < dateToZonedDateTime(certificateHolder.notBefore)) {
            throw CertificateException("Certificate is not yet valid")
        }
        if (dateToZonedDateTime(certificateHolder.notAfter) < now) {
            throw CertificateException("Certificate already expired")
        }
    }

    private fun validateCommonNamePresence() {
        if (certificateHolder.subject.getRDNs(BCStyle.CN).isEmpty()) {
            throw CertificateException("Subject should have a Common Name")
        }
    }

    /**
     * Get the certification path (aka certificate chain) between the current certificate and
     * one of the `trustedCAs`.
     *
     * @throws CertificateException if no path could be found
     */
    @Throws(CertificateException::class)
    fun getCertificationPath(
        intermediateCAs: Set<Certificate>,
        trustedCAs: Set<Certificate>
    ): Array<Certificate> {
        val pathBuilderResult = try {
            buildPath(intermediateCAs, trustedCAs)
        } catch (exc: CertPathBuilderException) {
            throw CertificateException("No certification path could be found", exc)
        }

        // Convert the Java certificates in the path back to Bouncy Castle instances
        val bcCertPath = pathBuilderResult.certPath.certificates.map {
            // It's insane we have to serialize + deserialize, but I couldn't find any other way
            // to convert a Java certificate to BouncyCastle
            X509CertificateHolder(it.encoded)
        }

        // Compute the root CA, since it's not included in the path. See:
        // https://stackoverflow.com/q/63051252/129437
        val firstCertAfterRoot = bcCertPath.last()
        val rootCA = trustedCAs.single {
            it.certificateHolder.subject == firstCertAfterRoot.issuer
        }

        // Convert the Java certificates back to the original BouncyCastle instances.
        val cAs = bcCertPath.slice(1..bcCertPath.lastIndex).map { copy ->
            intermediateCAs.single { original -> copy == original.certificateHolder }
        }.toMutableList()

        // Include the root certificate unless this is a self-signed certificate:
        if (rootCA != this) {
            cAs.add(rootCA)
        }

        return arrayOf(this, *cAs.toTypedArray())
    }

    @Throws(CertPathBuilderException::class)
    private fun buildPath(
        intermediateCAs: Set<Certificate>,
        trustedCAs: Set<Certificate>
    ): CertPathBuilderResult {
        // We have to start by converting all BC certificates to Java certificates because we
        // can't do this with BouncyCastle:
        // https://stackoverflow.com/q/63020771/129437
        val javaEndEntityCert = convertCertToJava(this)
        val javaIntermediateCACerts = intermediateCAs.map(::convertCertToJava)
        val javaTrustedCACerts = trustedCAs.map(::convertCertToJava)

        val trustAnchors = javaTrustedCACerts.map { TrustAnchor(it, null) }.toSet()

        val intermediateCertStore = CertStore.getInstance(
            "Collection",
            CollectionCertStoreParameters(javaIntermediateCACerts),
            BC_PROVIDER
        )

        val endEntitySelector = X509CertSelector()
        endEntitySelector.certificate = javaEndEntityCert

        val parameters: PKIXParameters = PKIXBuilderParameters(trustAnchors, endEntitySelector)
        parameters.isRevocationEnabled = false
        parameters.addCertStore(intermediateCertStore)

        val pathBuilder: CertPathBuilder = CertPathBuilder.getInstance("PKIX", BC_PROVIDER)
        return pathBuilder.build(parameters)
    }

    private fun convertCertToJava(certificate: Certificate) =
        bcToJavaCertificateConverter.getCertificate(certificate.certificateHolder)
}
