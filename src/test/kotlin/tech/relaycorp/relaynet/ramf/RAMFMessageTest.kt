package tech.relaycorp.relaynet.ramf

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.cms.parseCmsSignedData
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RAMFMessageTest {
    private val stubRecipientAddress = "04334"
    private val stubMessageId = "message-id"
    private val stubCreationDateUtc: ZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC"))
    private val stubTtl = 1
    private val stubPayload = "payload".toByteArray()

    private val stubSenderKeyPair = generateRSAKeyPair()
    private val stubSenderCertificate = issueStubCertificate(
        stubSenderKeyPair.public,
        stubSenderKeyPair.private
    )

    @Nested
    inner class Constructor {
        @Test
        fun `Recipient address should not span more than 1024 octets`() {
            val longRecipientAddress = "a".repeat(1025)
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    longRecipientAddress,
                    stubPayload,
                    stubSenderCertificate
                )
            }

            assertEquals(
                "Recipient address cannot span more than 1024 octets (got 1025)",
                exception.message
            )
        }

        @Test
        fun `Message id should not span more than 64 octets`() {
            val longMessageId = "a".repeat(65)
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    stubPayload,
                    stubSenderCertificate,
                    longMessageId
                )
            }

            assertEquals(
                "Message id cannot span more than 64 octets (got 65)",
                exception.message
            )
        }

        @Test
        fun `Message id should be honored if set`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate,
                stubMessageId
            )

            assertEquals(stubMessageId, message.messageId)
        }

        @Test
        fun `Message id should default to random UUID4 if unset`() {
            val message1 = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )
            val message2 = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )

            UUID.fromString(message1.messageId)
            UUID.fromString(message2.messageId)
            assertNotEquals(message1.messageId, message2.messageId)
        }

        @Test
        fun `Creation time should be honored if set`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate,
                creationDate = stubCreationDateUtc
            )

            assertEquals(stubCreationDateUtc, message.creationDate)
        }

        @Test
        fun `Creation date should default to current UTC time if unset`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )

            assertEquals("UTC", message.creationDate.zone.id)

            val now = ZonedDateTime.now(ZoneId.of("UTC"))
            val secondsAgo = now.minusSeconds(2)
            assertTrue(secondsAgo < message.creationDate)
            assertTrue(message.creationDate <= now)
        }

        @Test
        fun `TTL should not be negative`() {
            val negativeTtl = -1
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    stubPayload,
                    stubSenderCertificate,
                    ttl = negativeTtl
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
                    stubPayload,
                    stubSenderCertificate,
                    ttl = longTtl
                )
            }

            assertEquals(
                "TTL cannot be greater than $secondsIn180Days (got $longTtl)",
                exception.message
            )
        }

        @Test
        fun `TTL should be honored if set`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate,
                ttl = stubTtl
            )

            assertEquals(stubTtl, message.ttl)
        }

        @Test
        fun `TTL should default to 5 minutes if unset`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )

            val secondsIn5Min = 5 * 60
            assertEquals(secondsIn5Min, message.ttl)
        }

        @Test
        fun `Payload should not span more than 8 MiB`() {
            val octetsIn8Mib = 8388608
            val longPayloadLength = octetsIn8Mib + 1
            val longPayload = "a".repeat(longPayloadLength).toByteArray()
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    stubRecipientAddress,
                    longPayload,
                    stubSenderCertificate
                )
            }

            assertEquals(
                "Payload cannot span more than $octetsIn8Mib octets (got $longPayloadLength)",
                exception.message
            )
        }

        @Test
        fun `Sender certificate chain should be honored if set`() {
            val chain = setOf(stubSenderCertificate)
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate,
                senderCertificateChain = chain
            )

            assertEquals(chain, message.senderCertificateChain)
        }

        @Test
        fun `Sender certificate chain should default to an empty set if unset`() {
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )

            assertEquals(0, message.senderCertificateChain.size)
        }
    }

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should be delegated to serializer`() {
            val stubCaCertificate = issueStubCertificate(
                stubSenderKeyPair.public,
                stubSenderKeyPair.private
            )
            val message = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate,
                stubMessageId,
                stubCreationDateUtc,
                stubTtl,
                setOf(stubCaCertificate)
            )

            val serialization = STUB_SERIALIZER.serialize(message, stubSenderKeyPair.private)

            val messageDeserialized = StubRAMFMessage.deserialize(serialization)
            // TODO: Implement RAMFMessage.equals() and use it here
            assertEquals(message.recipientAddress, messageDeserialized.recipientAddress)
            assertEquals(message.messageId, messageDeserialized.messageId)
            assertEquals(
                message.creationDate.withNano(0).withZoneSameLocal(ZoneId.of("UTC")),
                messageDeserialized.creationDate
            )
            assertEquals(message.ttl, messageDeserialized.ttl)
            assertEquals(message.payload.asList(), messageDeserialized.payload.asList())
            assertEquals(message.senderCertificate, messageDeserialized.senderCertificate)
            assertEquals(
                setOf(message.senderCertificate, stubCaCertificate),
                messageDeserialized.senderCertificateChain
            )
        }

        @Nested
        inner class Hashing {
            private val stubMessage = StubRAMFMessage(
                stubRecipientAddress,
                stubPayload,
                stubSenderCertificate
            )

            @Test
            fun `SHA-256 should be used by default`() {
                val cmsSignedDataSerialized =
                    skipFormatSignature(stubMessage.serialize(stubSenderKeyPair.private))

                val cmsSignedData = parseCmsSignedData(cmsSignedDataSerialized)

                assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
                assertEquals(
                    HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA256],
                    cmsSignedData.digestAlgorithmIDs.first().algorithm
                )
            }

            @Test
            fun `Hashing algorithm should be customizable`() {
                val serialization = STUB_SERIALIZER.serialize(
                    stubMessage,
                    stubSenderKeyPair.private,
                    hashingAlgorithm = HashingAlgorithm.SHA384
                )
                val signedDataSerialized = skipFormatSignature(serialization)

                val signedData = parseCmsSignedData(signedDataSerialized)

                assertEquals(1, signedData.digestAlgorithmIDs.size)
                assertEquals(
                    HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA384],
                    signedData.digestAlgorithmIDs.first().algorithm
                )
            }
        }
    }
}
