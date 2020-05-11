package tech.relaycorp.relaynet.wrappers.x509

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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import tech.relaycorp.relaynet.dateToZonedDateTime
import tech.relaycorp.relaynet.wrappers.generateRandomBigInteger
import java.io.IOException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.sql.Date
import java.time.ZonedDateTime

class Certificate constructor(val certificateHolder: X509CertificateHolder) {
    companion object {
        private const val DEFAULT_ALGORITHM = "SHA256WithRSAEncryption"

        @Throws(CertificateException::class)
        fun issue(
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
                issuerCertificate.certificateHolder.issuer
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
            val ski = SubjectKeyIdentifier(subjectPublicKeyDigest)
            builder.addExtension(Extension.subjectKeyIdentifier, false, ski)

            val issuerPublicKeyDigest = if (issuerCertificate != null)
                getSHA256Digest(issuerCertificate.certificateHolder.subjectPublicKeyInfo.encoded)
            else
                subjectPublicKeyDigest
            val aki = AuthorityKeyIdentifier(issuerPublicKeyDigest)
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki)

            val signerBuilder = makeSigner(issuerPrivateKey)
            return Certificate(builder.build(signerBuilder))
        }

        @Throws(CertificateException::class)
        private fun buildDistinguishedName(commonName: String): X500Name {
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.CN, commonName)
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

        private fun makeSigner(issuerPrivateKey: PrivateKey): ContentSigner {
            val signatureAlgorithm =
                DefaultSignatureAlgorithmIdentifierFinder().find(DEFAULT_ALGORITHM)
            val digestAlgorithm = DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val privateKeyParam: AsymmetricKeyParameter =
                PrivateKeyFactory.createKey(issuerPrivateKey.encoded)
            val contentSignerBuilder =
                BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
            return contentSignerBuilder.build(privateKeyParam)
        }

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

    val commonName: String
        get() {
            val commonNames = certificateHolder.subject.getRDNs(BCStyle.CN)
            return commonNames.first().first.value.toString()
        }

    val subjectPrivateAddress: String
        get() {
            val digestHex = getSHA256Digest(certificateHolder.subjectPublicKeyInfo.encoded)
                .joinToString("") { "%02x".format(it) }
            return "0$digestHex"
        }

    override fun equals(other: Any?): Boolean {
        if (other !is Certificate) {
            return false
        }
        return certificateHolder == other.certificateHolder
    }

    override fun hashCode(): Int {
        return certificateHolder.hashCode()
    }

    fun serialize(): ByteArray {
        return certificateHolder.encoded
    }

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

private fun getSHA256Digest(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}
