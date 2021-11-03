package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.wrappers.cms.SessionlessEnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class EncryptedPayload : Payload {
    fun encrypt(
        recipientCertificate: Certificate,
        symmetricCipher: SymmetricCipher = SymmetricCipher.AES_128
    ): ByteArray {
        val envelopedData = SessionlessEnvelopedData.encrypt(
            this.serializePlaintext(),
            recipientCertificate,
            symmetricCipher
        )
        return envelopedData.serialize()
    }
}
