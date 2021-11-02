package tech.relaycorp.relaynet.ramf

import java.io.InputStream
import java.nio.charset.Charset
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.messages.payloads.StubEncryptedPayload
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal val STUB_SERIALIZER = RAMFSerializer(32, 0)

internal class StubEncryptedRAMFMessage(
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : EncryptedRAMFMessage<StubEncryptedPayload>(
    STUB_SERIALIZER,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    override fun deserializePayload(payloadPlaintext: ByteArray) =
        StubEncryptedPayload(payloadPlaintext.toString(Charset.forName("ASCII")))

    companion object : RAMFMessageCompanion<StubEncryptedRAMFMessage> {
        override fun deserialize(serialization: ByteArray) =
            STUB_SERIALIZER.deserialize(serialization, ::StubEncryptedRAMFMessage)

        override fun deserialize(serialization: InputStream) =
            STUB_SERIALIZER.deserialize(serialization, ::StubEncryptedRAMFMessage)
    }
}
