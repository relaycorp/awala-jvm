package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.wrappers.cms.SessionlessEnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate

public abstract class EncryptedPayload : Payload {
    public fun encrypt(
        recipientCertificate: Certificate,
        symmetricEncryptionAlgorithm: SymmetricEncryption = SymmetricEncryption.AES_128
    ): ByteArray {
        val envelopedData = SessionlessEnvelopedData.encrypt(
            this.serializePlaintext(),
            recipientCertificate,
            symmetricEncryptionAlgorithm
        )
        return envelopedData.serialize()
    }
}
