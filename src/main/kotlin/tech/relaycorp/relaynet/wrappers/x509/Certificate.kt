package tech.relaycorp.relaynet.wrappers.x509

import java.security.PrivateKey
import java.security.PublicKey
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

class Certificate constructor(_certificateHolder: X509CertificateHolder) {
    val certificateHolder: X509CertificateHolder = _certificateHolder

    companion object {
        private const val DEFAULT_ALGORITHM = "SHA256WithRSAEncryption"
        private const val MAX_PATH_LENGTH_CONSTRAINT = 2

        @Throws(CertificateException::class)
        fun issue(
            commonName: X500Name?,
            issuerPrivateKey: PrivateKey,
            subjectPublicKey: PublicKey,
            serialNumber: Long,
            validityStartDate: LocalDateTime = LocalDateTime.now(),
            validityEndDate: LocalDateTime = validityStartDate.plusMonths(1),
            isCA: Boolean = false,
            pathLenConstraint: Int = MAX_PATH_LENGTH_CONSTRAINT
        ): Certificate {
            // validate inputs
            if (validityStartDate >= validityEndDate) {
                throw CertificateException("The end date must be later than the start date")
            }

            val issuer = X500Name.getInstance(commonName)
            val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.encoded)
            val signatureAlgorithm = DefaultSignatureAlgorithmIdentifierFinder().find(DEFAULT_ALGORITHM)
            val digestAlgorithm = DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val privateKeyParam: AsymmetricKeyParameter = PrivateKeyFactory.createKey(issuerPrivateKey.encoded)
            val contentSignerBuilder = BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
            val signerBuilder = contentSignerBuilder.build(privateKeyParam)

            val builder = X509v3CertificateBuilder(
                issuer,
                serialNumber.toBigInteger(),
                Date.valueOf(validityStartDate.toLocalDate()),
                Date.valueOf(validityEndDate.toLocalDate()),
                Locale.ENGLISH,
                commonName,
                subjectPublicKeyInfo
            )

            return Certificate(builder.build(signerBuilder))
        }

        @Throws(CertificateException::class)
        fun buildX500Name(cName: String): X500Name {
            if (cName.isEmpty()) {
                throw CertificateException("Invalid CName in X500 Name")
            }
            val builder = X500NameBuilder(BCStyle.INSTANCE)
            builder.addRDN(BCStyle.C, cName)
            return builder.build()
        }
    }
}

// data class FullCertificateIssuanceOptions(){
//    var commonName: X500Name?
//    var issuerPrivateKey: PrivateKey
//    var subjectPublicKey: PublicKey
//    var serialNumber: Long
//    var validityStartDate: LocalDateTime
//    var validityEndDate: LocalDateTime
//    var isCA: Boolean?
//    var issuerCertificate: Certificate?
//    var pathLenConstraint: Int
//
// fun build(commonName: X500Name?,
//    issuerPrivateKey: PrivateKey,
//    subjectPublicKey: PublicKey,
//    serialNumber: Long = generateRandom64BitValue(),
//    validityStartDate: LocalDateTime = LocalDateTime.now(),
//    validityEndDate: LocalDateTime = validityStartDate.plusMonths(1),
//    isCA: Boolean? = false,
//    issuerCertificate: Certificate?,
//    pathLenConstraint: Int = MAX_PATH_LENGTH_CONSTRAINT){
// }
// }
