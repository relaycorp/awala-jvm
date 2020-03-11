package tech.relaycorp.relaynet.cms

import java.security.PrivateKey
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import tech.relaycorp.relaynet.x509.Certificate

@Throws(SignedDataException::class)
fun sign(plaintext: ByteArray, signerPrivateKey: PrivateKey, signerCertificate: Certificate): ByteArray {
    val signedDataGenerator = CMSSignedDataGenerator()

    val contentSigner: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(signerPrivateKey)
    val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
        JcaDigestCalculatorProviderBuilder()
            .build()
    ).build(contentSigner, signerCertificate.certificateHolder)
    signedDataGenerator.addSignerInfoGenerator(
        signerInfoGenerator
    )

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
