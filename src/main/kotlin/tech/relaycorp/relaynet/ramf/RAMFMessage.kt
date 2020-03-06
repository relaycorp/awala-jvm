package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

val berDateTimeFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

private const val MAX_RECIPIENT_ADDRESS_LENGTH = 1023
private const val MAX_MESSAGE_ID_LENGTH = 255
private const val MAX_TTL = 15552000
private const val MAX_PAYLOAD_LENGTH = 8388608

internal abstract class RAMFMessage(
    val recipientAddress: String,
    val messageId: String,
    val creationTime: ZonedDateTime,
    val ttl: Int,
    val payload: ByteArray
) {
    init {
        if (MAX_RECIPIENT_ADDRESS_LENGTH < recipientAddress.length) {
            throw RAMFException(
                "Recipient address cannot span more than $MAX_RECIPIENT_ADDRESS_LENGTH octets (got ${recipientAddress.length})"
            )
        }
        if (MAX_MESSAGE_ID_LENGTH < messageId.length) {
            throw RAMFException(
                "Message id cannot span more than $MAX_MESSAGE_ID_LENGTH octets (got ${messageId.length})"
            )
        }
        if (ttl < 0) {
            throw RAMFException("TTL cannot be negative (got $ttl)")
        }
        if (MAX_TTL < ttl) {
            throw RAMFException(
                "TTL cannot be greater than $MAX_TTL (got $ttl)"
            )
        }
        if (MAX_PAYLOAD_LENGTH < payload.size) {
            throw RAMFException(
                "Payload cannot span more than $MAX_PAYLOAD_LENGTH octets (got ${payload.size})"
            )
        }
    }

    // TODO: Write instance method serialize() once deserialization is complete
    // so that the deserialization() function can be used in the tests

    companion object : RAMFSerializer(0, 0)
}
