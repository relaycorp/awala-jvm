package tech.relaycorp.relaynet.messages

import java.io.InputStream
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.messages.payloads.CargoCollectionRequest
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate

private val SERIALIZER = RAMFSerializer(0x44, 0x00)

/**
 * Cargo Collection Authorization (CCA)
 */
class CargoCollectionAuthorization(
    recipient: Recipient,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null,
) : EncryptedRAMFMessage<CargoCollectionRequest>(
        SERIALIZER,
        recipient,
        payload,
        senderCertificate,
        messageId,
        creationDate,
        ttl,
        senderCertificateChain,
    ) {
    override fun deserializePayload(payloadPlaintext: ByteArray) =
        CargoCollectionRequest.deserialize(payloadPlaintext)

    companion object : RAMFMessageCompanion<CargoCollectionAuthorization> {
        /**
         * Deserialize a CCA
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: ByteArray) =
            SERIALIZER.deserialize(serialization, ::CargoCollectionAuthorization)

        /**
         * Deserialize a CCA
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: InputStream) =
            SERIALIZER.deserialize(serialization, ::CargoCollectionAuthorization)
    }
}
