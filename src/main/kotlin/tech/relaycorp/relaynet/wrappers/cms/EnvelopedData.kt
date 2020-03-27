package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter
import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private val cmsContentEncryptionAlgorithm = mapOf(
    SymmetricEncryption.AES_GCM_128 to CMSAlgorithm.AES128_GCM,
    SymmetricEncryption.AES_GCM_192 to CMSAlgorithm.AES192_GCM,
    SymmetricEncryption.AES_GCM_256 to CMSAlgorithm.AES256_GCM
)

sealed class EnvelopedData(val bcEnvelopedData: CMSEnvelopedData) {
    fun serialize(): ByteArray {
        return bcEnvelopedData.encoded
    }
}

class SessionlessEnvelopedData(bcEnvelopedData: CMSEnvelopedData) : EnvelopedData(bcEnvelopedData) {
    companion object {
        fun encrypt(
            plaintext: ByteArray,
            recipientCertificate: Certificate,
            symmetricEncryptionAlgorithm: SymmetricEncryption = SymmetricEncryption.AES_GCM_128
        ): EnvelopedData {
            // We'd ideally take the plaintext as an InputStream but the Bouncy Castle class
            // CMSProcessableInputStream doesn't seem to be accessible here
            val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

            val x509Certificate = JcaX509CertificateConverter()
                .getCertificate(recipientCertificate.certificateHolder)
            val paramsConverter = JcaAlgorithmParametersConverter()
            val transKeyGen = JceKeyTransRecipientInfoGenerator(
                x509Certificate,
                paramsConverter.getAlgorithmIdentifier(
                    PKCSObjectIdentifiers.id_RSAES_OAEP,
                    OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        PSource.PSpecified.DEFAULT
                    )
                )
            )
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(
                transKeyGen.setProvider(
                    BouncyCastleProvider()
                )
            )

            val msg = CMSProcessableByteArray(plaintext)
            val contentEncryptionAlgorithm =
                cmsContentEncryptionAlgorithm[symmetricEncryptionAlgorithm]
            val jceCMSContentEncryptorBuilder =
                JceCMSContentEncryptorBuilder(contentEncryptionAlgorithm)
            val encryptor = jceCMSContentEncryptorBuilder.setProvider(
                BouncyCastleProvider()
            ).build()
            val bcEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor)

            return SessionlessEnvelopedData(
                bcEnvelopedData
            )
        }
    }
}
