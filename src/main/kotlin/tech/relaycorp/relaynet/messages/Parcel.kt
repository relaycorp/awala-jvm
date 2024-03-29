package tech.relaycorp.relaynet.messages

import java.io.InputStream
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.messages.payloads.ServiceMessage
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal val PARCEL_SERIALIZER = RAMFSerializer(0x50, 0x00)

/**
 * Parcel
 */
class Parcel(
    recipient: Recipient,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null,
) : EncryptedRAMFMessage<ServiceMessage>(
        PARCEL_SERIALIZER,
        recipient,
        payload,
        senderCertificate,
        messageId,
        creationDate,
        ttl,
        senderCertificateChain,
    ) {
    override fun deserializePayload(payloadPlaintext: ByteArray) =
        ServiceMessage.deserialize(payloadPlaintext)

    companion object : RAMFMessageCompanion<Parcel> {
        /**
         * Deserialize parcel
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: ByteArray) =
            PARCEL_SERIALIZER.deserialize(serialization, ::Parcel)

        /**
         * Deserialize parcel
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: InputStream) =
            PARCEL_SERIALIZER.deserialize(serialization, ::Parcel)
    }
}
