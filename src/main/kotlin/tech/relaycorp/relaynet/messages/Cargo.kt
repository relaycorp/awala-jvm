package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.messages.payloads.CargoMessageSet
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.InputStream
import java.time.ZonedDateTime

private val SERIALIZER = RAMFSerializer(0x43, 0x00)

/**
 * Cargo
 */
public class Cargo(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : EncryptedRAMFMessage<CargoMessageSet>(
    SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    override fun deserializePayload(payloadPlaintext: ByteArray) =
        CargoMessageSet.deserialize(payloadPlaintext)

    public companion object : RAMFMessageCompanion<Cargo> {
        /**
         * Deserialize cargo
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: ByteArray): Cargo =
            SERIALIZER.deserialize(serialization, ::Cargo)

        /**
         * Deserialize cargo
         */
        @JvmStatic
        @Throws(RAMFException::class)
        override fun deserialize(serialization: InputStream): Cargo =
            SERIALIZER.deserialize(serialization, ::Cargo)
    }
}
