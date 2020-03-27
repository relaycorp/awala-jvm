package tech.relaycorp.relaynet.cms

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import tech.relaycorp.relaynet.wrappers.x509.Certificate

sealed class EnvelopedData(val bcEnvelopedData: CMSEnvelopedData) {
    companion object {
        fun encrypt(plaintext: ByteArray, recipientCertificate: Certificate): EnvelopedData {
            // We'd ideally take the plaintext as an InputStream but the Bouncy Castle class
            // CMSProcessableInputStream doesn't seem to be accessible here
            val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

            val x509Certificate = JcaX509CertificateConverter()
                .getCertificate( recipientCertificate.certificateHolder )
            val transKeyGen =
                JceKeyTransRecipientInfoGenerator(x509Certificate)
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen)

            val msg = CMSProcessableByteArray(plaintext)
            val encryptor = JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build()
            val bcEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor)
            return SessionlessEnvelopedData(bcEnvelopedData)
        }
    }
}

class SessionlessEnvelopedData(bcEnvelopedData: CMSEnvelopedData) : EnvelopedData(bcEnvelopedData)