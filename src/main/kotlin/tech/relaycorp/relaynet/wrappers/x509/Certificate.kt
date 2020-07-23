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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.dateToZonedDateTime
import tech.relaycorp.relaynet.getSHA256Digest
import tech.relaycorp.relaynet.getSHA256DigestHex
import tech.relaycorp.relaynet.wrappers.generateRandomBigInteger
import java.io.IOException
import java.security.PrivateKey
import java.security.PublicKey
import java.sql.Date
import java.time.ZonedDateTime

/**
 * Relaynet PKI Certificate.
 *
 * @param certificateHolder Bouncy Castle representation of the X.509 certificate
 */
class Certificate constructor(val certificateHolder: X509CertificateHolder) {
    companion object {
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
}
