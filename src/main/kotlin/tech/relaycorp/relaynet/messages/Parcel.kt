package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.messages.payloads.ServiceMessage
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.InputStream
import java.time.ZonedDateTime

private val SERIALIZER = RAMFSerializer(0x50, 0x00)

/**
 * Parcel
 */
class Parcel(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : RAMFMessage<ServiceMessage>(
    SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    override fun deserializePayload(payloadPlaintext: ByteArray): ServiceMessage {
        TODO("Not yet implemented")
    }

    companion object : RAMFMessageCompanion<Parcel> {
        /**
         * Deserialize parcel
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: ByteArray) =
            SERIALIZER.deserialize(serialization, ::Parcel)

        /**
         * Deserialize parcel
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: InputStream) =
            SERIALIZER.deserialize(serialization, ::Parcel)
    }
}
