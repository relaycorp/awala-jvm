package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.wrappers.cms.SessionEnvelopedData

abstract class EncryptedPayload : Payload {
    fun encrypt(
        recipientSessionKey: SessionKey,
        senderSessionKeyPair: SessionKeyPair,
        symmetricCipher: SymmetricCipher = SymmetricCipher.AES_128,
        hashingAlgorithm: HashingAlgorithm = HashingAlgorithm.SHA256,
    ): ByteArray {
        val envelopedData = SessionEnvelopedData.encrypt(
            serializePlaintext(),
            recipientSessionKey,
            senderSessionKeyPair,
            symmetricCipher,
            hashingAlgorithm
        )
        return envelopedData.serialize()
    }
}
