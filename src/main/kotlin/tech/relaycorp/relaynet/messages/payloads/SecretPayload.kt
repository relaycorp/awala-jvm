package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class SecretPayload : Payload {
    fun encrypt(
        recipientCertificate: Certificate,
        symmetricEncryptionAlgorithm: SymmetricEncryption = SymmetricEncryption.AES_128
    ): ByteArray {
        TODO()
    }
}
