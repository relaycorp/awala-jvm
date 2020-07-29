package tech.relaycorp.relaynet.crypto

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.HashingAlgorithm
import java.security.PrivateKey

/**
 * Relaynet-specific, CMS SignedData representation.
 */
class SignedData(internal val bcSignedData: CMSSignedData) {
    fun serialize(): ByteArray = bcSignedData.encoded

    companion object {
        private val signatureAlgorithmMap = mapOf(
            HashingAlgorithm.SHA256 to "SHA256WITHRSAANDMGF1",
            HashingAlgorithm.SHA384 to "SHA384WITHRSAANDMGF1",
            HashingAlgorithm.SHA512 to "SHA512WITHRSAANDMGF1"
        )

        fun sign(
            plaintext: ByteArray,
            signerPrivateKey: PrivateKey,
            signerCertificate: X509CertificateHolder,
            caCertificates: Set<X509CertificateHolder> = setOf(),
            hashingAlgorithm: HashingAlgorithm? = null
        ): SignedData {
            val signedDataGenerator = CMSSignedDataGenerator()

            val algorithm = hashingAlgorithm ?: HashingAlgorithm.SHA256
            val signerBuilder =
                JcaContentSignerBuilder(signatureAlgorithmMap[algorithm]).setProvider(BC_PROVIDER)
            val contentSigner: ContentSigner = signerBuilder.build(signerPrivateKey)
            val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
                JcaDigestCalculatorProviderBuilder()
                    .build()
            ).build(contentSigner, signerCertificate)
            signedDataGenerator.addSignerInfoGenerator(
                signerInfoGenerator
            )

            val certs = JcaCertStore(
                listOf(signerCertificate, *caCertificates.toTypedArray())
            )
            signedDataGenerator.addCertificates(certs)

            val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
            val bcSignedData = signedDataGenerator.generate(plaintextCms, true)
            return SignedData(bcSignedData)
        }
    }
}
