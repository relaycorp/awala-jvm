package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime

internal class StubRAMFMessage(
    recipientAddress: String,
    messageId: String,
    creationTime: ZonedDateTime,
    ttl: Int,
    payload: ByteArray
) : RAMFMessage(recipientAddress, messageId, creationTime, ttl, payload) {
    companion object : RAMFSerializer(0, 0)
}
