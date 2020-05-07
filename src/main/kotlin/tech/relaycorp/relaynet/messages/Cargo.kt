package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.ramf.RAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.time.ZonedDateTime

private val SERIALIZER = RAMFSerializer(0x43, 0x00)

class Cargo(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : RAMFMessage(
    SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    companion object : RAMFMessageCompanion<Cargo> {
        @JvmStatic
        override fun deserialize(serialization: ByteArray): Cargo {
            return SERIALIZER.deserialize(serialization, ::Cargo)
        }
    }
}
