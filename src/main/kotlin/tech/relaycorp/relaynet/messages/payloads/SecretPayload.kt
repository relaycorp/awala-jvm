package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey

internal interface SecretPayload {
    fun encrypt(
        privateKey: PrivateKey,
        recipientCertificate: Certificate,
        symmetricEncryptionAlgorithm: SymmetricEncryption = SymmetricEncryption.AES_128
    ): EnvelopedData
}
