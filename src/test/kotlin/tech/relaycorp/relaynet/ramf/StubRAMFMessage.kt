package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.InputStream
import java.nio.charset.Charset
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
) : RAMFMessage<StubPayload>(
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
        StubPayload(payloadPlaintext.toString(Charset.forName("ASCII")))

    companion object : RAMFMessageCompanion<StubRAMFMessage> {
        override fun deserialize(serialization: ByteArray) =
            STUB_SERIALIZER.deserialize(serialization, ::StubRAMFMessage)

        override fun deserialize(serialization: InputStream) =
            STUB_SERIALIZER.deserialize(serialization, ::StubRAMFMessage)
    }
}
