// TODO: Remove this file
// The final implementation can be found in https://github.com/relaycorp/relaynet-jvm/pull/22

package tech.relaycorp.relaynet.x509

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import tech.relaycorp.relaynet.x509.Certificate.Companion.MAX_PATH_LENGTH_CONSTRAINT
import tech.relaycorp.relaynet.x509.CryptoUtil.Companion.generateRandom64BitValue
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.sql.Date
import java.time.LocalDateTime
import java.util.Locale

class Certificate constructor (val certificateHolder: X509CertificateHolder?) {

    companion object {
        val MAX_PATH_LENGTH_CONSTRAINT = 2
        val DEFAULT_ALGORITHM = "SHA256WithRSAEncryption"

        @Throws(CertificateError::class)
        fun issue(options: FullCertificateIssuanceOptions): Certificate {
            val start = options.validityStartDate
            val end = options.validityEndDate
            // validate inputs
            if (start >= end) {
                throw CertificateError("The end date must be later than the start date")
            }

            val issuer = X500Name.getInstance(options.commonName)
            val serial = options.serialNumber

            val subject = options.commonName
            val pubkey = options.subjectPublicKey
            val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pubkey.getEncoded())

            val signatureAlgorithm = DefaultSignatureAlgorithmIdentifierFinder().find(DEFAULT_ALGORITHM)
            val digestAlgorithm = DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val privateKeyParam: AsymmetricKeyParameter = PrivateKeyFactory.createKey(options.issuerPrivateKey.encoded)
            val contentSignerBuilder = BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
            val signerBuilder = contentSignerBuilder.build(privateKeyParam)

            val builder = X509v3CertificateBuilder(issuer,
                    serial.toBigInteger(), Date.valueOf(start.toLocalDate()), Date.valueOf(end.toLocalDate()), Locale.ENGLISH, subject, subjectPublicKeyInfo)

            return Certificate(builder.build(signerBuilder))
        }

        @Throws(CertificateError::class)
        fun buildX500Name(cName: String): X500Name {
            if (cName.length <= 0) {
                throw CertificateError("Invalid CName in X500 Name")
            }
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.C, cName)
            return builder.build() ?: throw CertificateError("Invalid X500 Name")
        }
    }
}

data class FullCertificateIssuanceOptions(
    var commonName: X500Name?,
    var issuerPrivateKey: PrivateKey,
    var subjectPublicKey: PublicKey,
    var serialNumber: Long = generateRandom64BitValue(),
    var validityStartDate: LocalDateTime = LocalDateTime.now(),
    var validityEndDate: LocalDateTime = validityStartDate.plusMonths(1),
    var isCA: Boolean? = false,
    var issuerCertificate: Certificate?,
    var pathLenConstraint: Int = MAX_PATH_LENGTH_CONSTRAINT
)

class Keys {

    companion object {
        private val DEFAULT_KEY_SIZE: Int = 2048
        fun generateRSAKeyPair(modulus: Int): KeyPair {
            val keyGen = KeyPairGenerator.getInstance("RSA")
            keyGen.initialize(maxOf(modulus,
                DEFAULT_KEY_SIZE
            )) // `modulus` should be >= 2048 and default to 2048
            return keyGen.generateKeyPair()
        }
    }
}

class CryptoUtil {
    companion object {
        fun generateRandom64BitValue(): Long {
            val random = SecureRandom()
            return random.nextLong()
        }
    }
}

open class RelaynetError : Exception()

open class CertificateError(override val message: String?) : RelaynetError()
