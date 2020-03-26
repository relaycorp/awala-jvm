package tech.relaycorp.relaynet.ramf

import java.security.PrivateKey
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal val STUB_SERIALIZER = RAMFSerializer(32, 0)

internal class StubRAMFMessage(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationTime: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : RAMFMessage(
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationTime,
    ttl,
    senderCertificateChain
) {
    override fun serialize(senderPrivateKey: PrivateKey): ByteArray {
        return STUB_SERIALIZER.serialize(this, senderPrivateKey)
    }

    companion object {
        fun deserialize(serialization: ByteArray): StubRAMFMessage {
            return STUB_SERIALIZER.deserialize(serialization, ::StubRAMFMessage)
        }
    }
}
