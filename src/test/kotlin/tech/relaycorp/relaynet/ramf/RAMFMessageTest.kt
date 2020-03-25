package tech.relaycorp.relaynet.ramf

import java.time.LocalDateTime
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class RAMFMessageTest {
    private val stubRecipientAddress = "04334"
    private val stubMessageId = "message-id"
    private val stubCreationTimeUtc: ZonedDateTime = ZonedDateTime.now()
    private val stubTtl = 1
    private val stubPayload = "payload".toByteArray()

    private val stubSenderKeyPair = generateRSAKeyPair()
    private val stubSenderCertificate = Certificate.issue(
        "the subject",
        stubSenderKeyPair.private,
        stubSenderKeyPair.public,
        LocalDateTime.now().plusDays(1)
    )

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
                    stubPayload,
                    stubSenderCertificate
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
                    stubPayload,
                    stubSenderCertificate
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
                    stubPayload,
                    stubSenderCertificate
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
                    stubPayload,
                    stubSenderCertificate
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
                    longPayload,
                    stubSenderCertificate
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
        fun `Serialization should be delegated to companion object`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubMessageId,
                stubCreationTimeUtc,
                stubTtl,
                stubPayload,
                stubSenderCertificate
            )

            val serialization = message.serialize(stubSenderKeyPair.private)

            val messageDeserialized = StubRAMFMessage.deserialize(serialization)
            assertEquals(message, messageDeserialized)
        }
    }
}
