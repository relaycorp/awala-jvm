package tech.relaycorp.relaynet.cms

import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.x509.Certificate
import java.security.PrivateKey

private val signatureAlgorithmMap = mapOf(
    HashingAlgorithm.SHA256 to "SHA256withRSA",
    HashingAlgorithm.SHA384 to "SHA384withRSA",
    HashingAlgorithm.SHA512 to "SHA512withRSA"
)

@Throws(SignedDataException::class)
fun sign(
    plaintext: ByteArray,
    signerPrivateKey: PrivateKey,
    signerCertificate: Certificate,
    caCertificates: Set<Certificate> = setOf(),
    hashingAlgorithm: HashingAlgorithm = HashingAlgorithm.SHA256
): ByteArray {
    val signedDataGenerator = CMSSignedDataGenerator()

    val signerBuilder = JcaContentSignerBuilder(signatureAlgorithmMap[hashingAlgorithm])
    val contentSigner: ContentSigner = signerBuilder.build(signerPrivateKey)
    val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
        JcaDigestCalculatorProviderBuilder()
            .build()
    ).build(contentSigner, signerCertificate.certificateHolder)
    signedDataGenerator.addSignerInfoGenerator(
        signerInfoGenerator
    )

    val caCertHolders = caCertificates.map { c -> c.certificateHolder }
    val certs = JcaCertStore(
        listOf(
            signerCertificate.certificateHolder,
            *caCertHolders.toTypedArray()
        )
    )
    signedDataGenerator.addCertificates(certs)

    val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
    val cmsSignedData = signedDataGenerator.generate(plaintextCms, true)
    return cmsSignedData.encoded
}

data class SignatureVerification(
    val signerCertificate: Certificate,
    val attachedCertificates: Array<Certificate>
)

@Throws(SignedDataException::class)
fun verifySignature(): SignatureVerification {
    throw NotImplementedError()
}
