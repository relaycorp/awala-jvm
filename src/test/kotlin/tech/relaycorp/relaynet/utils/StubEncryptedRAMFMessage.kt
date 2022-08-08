package tech.relaycorp.relaynet.utils

import java.io.InputStream
import java.nio.charset.Charset
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage
import tech.relaycorp.relaynet.ramf.RAMFMessageCompanion
import tech.relaycorp.relaynet.ramf.RAMFSerializer
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class StubEncryptedRAMFMessage(
    recipient: Recipient,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String? = null,
    creationDate: ZonedDateTime? = null,
    ttl: Int? = null,
    senderCertificateChain: Set<Certificate>? = null
) : EncryptedRAMFMessage<StubEncryptedPayload>(
    SERIALIZER,
    recipient,
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
        internal val SERIALIZER = RAMFSerializer(32, 0)

        override fun deserialize(serialization: ByteArray) =
            SERIALIZER.deserialize(serialization, ::StubEncryptedRAMFMessage)

        override fun deserialize(serialization: InputStream) =
            SERIALIZER.deserialize(serialization, ::StubEncryptedRAMFMessage)
    }
}
