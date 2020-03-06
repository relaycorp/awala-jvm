package tech.relaycorp.relaynet

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.sql.Date
import java.time.LocalDateTime
import java.util.Locale
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
import tech.relaycorp.relaynet.Certificate.Companion.MAX_PATH_LENGTH_CONSTRAINT
import tech.relaycorp.relaynet.CryptoUtil.Companion.generateRandom64BitValue

class Certificate constructor (certificateHolder: X509CertificateHolder?) {

    companion object {
        val MAX_PATH_LENGTH_CONSTRAINT = 2
        val DEFAULT_ALGORITHM = "SHA256WithRSAEncryption"

        fun issue(options: FullCertificateIssuanceOptions): Certificate {

            val issuer = X500Name.getInstance(options.commonName)
            val serial = options.serialNumber
            val start = options.validityStartDate
            val end = options.validityEndDate
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
        fun buildX500Name(cName: String, oName: String, lName: String, stName: String, email: String? = "info@relaycorp.tech"): X500Name {
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.C, cName)
            builder.addRDN(BCStyle.O, oName)
            builder.addRDN(BCStyle.L, lName)
            builder.addRDN(BCStyle.ST, stName)
            builder.addRDN(BCStyle.E, email)
            return builder.build() ?: throw CertificateError("Invalid X500 Name", null)
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
            keyGen.initialize(maxOf(modulus, DEFAULT_KEY_SIZE)) // `modulus` should be >= 2048 and default to 2048
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

open class CertificateError(override val message: String?, override val cause: Throwable?) : RelaynetError()
