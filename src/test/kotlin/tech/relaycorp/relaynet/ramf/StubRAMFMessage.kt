package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class StubRAMFMessage(
    recipientAddress: String,
    messageId: String,
    creationTime: ZonedDateTime,
    ttl: Int,
    payload: ByteArray,
    senderCertificate: Certificate
) : RAMFMessage(recipientAddress, messageId, creationTime, ttl, payload, senderCertificate) {
    companion object : RAMFSerializer<StubRAMFMessage>(32, 0, ::StubRAMFMessage)
}
