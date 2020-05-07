package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.time.ZonedDateTime

internal val STUB_SERIALIZER = RAMFSerializer(32, 0)

internal class StubRAMFMessage(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : RAMFMessage(
    STUB_SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    companion object {
        fun deserialize(serialization: ByteArray): StubRAMFMessage {
            return STUB_SERIALIZER.deserialize(serialization, ::StubRAMFMessage)
        }
    }
}
