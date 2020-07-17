package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.messages.payloads.EmptyPayloadPlaintext
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.InputStream
import java.time.ZonedDateTime

private val SERIALIZER = RAMFSerializer(0x44, 0x00)

/**
 * Cargo Collection Authorization (CCA)
 */
class CargoCollectionAuthorization(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : RAMFMessage<EmptyPayloadPlaintext>(
    SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    override fun deserializePayload(payloadPlaintext: ByteArray): EmptyPayloadPlaintext {
        TODO("Not yet implemented")
    }

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
