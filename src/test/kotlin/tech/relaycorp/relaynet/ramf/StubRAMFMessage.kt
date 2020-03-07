package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime

internal class StubRAMFMessage(
    recipientAddress: String,
    messageId: String,
    creationTime: ZonedDateTime,
    ttl: Int,
    payload: ByteArray
) : RAMFMessage(recipientAddress, messageId, creationTime, ttl, payload) {
    companion object : RAMFSerializer<StubRAMFMessage>(0, 0, ::StubRAMFMessage)
}
