package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows

class RAMFMessageTest {
    val stubRecipientAddress = "04334"
    val stubMessageId = "message-id"
    val stubCreationTimeUtc: ZonedDateTime = ZonedDateTime.now()
    val stubTtl = 1
    val stubPayload = "payload".toByteArray()

    @Nested
    inner class Constructor {
        @Test
        fun `Recipient address should not span more than 1023 octets`() {
            val longRecipientAddress = "a".repeat(1024)
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    longRecipientAddress,
                    stubMessageId,
                    stubCreationTimeUtc,
                    stubTtl,
                    stubPayload
                )
            }

            assertEquals(
                "Recipient address cannot span more than 1023 octets (got 1024)",
                exception.message
            )
        }

        @Test
        fun `Message id should not span more than 255 octets`() {
            val longMessageId = "a".repeat(256)
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    longMessageId,
                    stubCreationTimeUtc,
                    stubTtl,
                    stubPayload
                )
            }

            assertEquals(
                "Message id cannot span more than 255 octets (got 256)",
                exception.message
            )
        }

        @Test
        fun `TTL should not be negative`() {
            val negativeTtl = -1
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    stubMessageId,
                    stubCreationTimeUtc,
                    negativeTtl,
                    stubPayload
                )
            }

            assertEquals("TTL cannot be negative (got $negativeTtl)", exception.message)
        }

        @Test
        fun `TTL should not be greater than 180 days`() {
            val secondsIn180Days = 15552000
            val longTtl = secondsIn180Days + 1
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    stubMessageId,
                    stubCreationTimeUtc,
                    longTtl,
                    stubPayload
                )
            }

            assertEquals(
                "TTL cannot be greater than $secondsIn180Days (got $longTtl)",
                exception.message
            )
        }

        @Test
        fun `Payload should not span more than 8 MiB`() {
            val octetsIn8Mib = 8388608
            val longPayloadLength = octetsIn8Mib + 1
            val longPayload = "a".repeat(longPayloadLength).toByteArray()
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    stubMessageId,
                    stubCreationTimeUtc,
                    stubTtl,
                    longPayload
                )
            }

            assertEquals(
                "Payload cannot span more than $octetsIn8Mib octets (got $longPayloadLength)",
                exception.message
            )
        }
    }

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should use format signature specified in companion object`() {
            val message =
                StubRAMFMessage(stubRecipientAddress, stubMessageId, stubCreationTimeUtc, stubTtl, stubPayload)

            val serialization = message.serialize()

            val expectedSerialization = StubRAMFMessage.serialize(
                RAMFFieldSet(
                    stubRecipientAddress, stubMessageId, stubCreationTimeUtc, stubTtl, stubPayload
                )
            )
            assert(serialization contentEquals expectedSerialization)
        }
    }
}
