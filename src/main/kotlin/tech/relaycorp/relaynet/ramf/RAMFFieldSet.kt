package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime

data class RAMFFieldSet(
    val recipientAddress: String,
    val messageId: String,
    val creationTime: ZonedDateTime,
    val ttl: Int,
    val payload: ByteArray
)
