package tech.relaycorp.relaynet.ramf

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.cms.parseCmsSignedData
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RAMFMessageTest {
    private val recipientAddress = "04334"
    private val messageId = "message-id"
    private val creationDateUtc: ZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC"))
    private val ttl = 1
    private val payload = "payload".toByteArray()

    private val senderKeyPair = generateRSAKeyPair()
    private val senderCertificate =
        issueStubCertificate(senderKeyPair.public, senderKeyPair.private)

    @Nested
    inner class Constructor {
        @Test
        fun `Recipient address should not span more than 1024 octets`() {
            val longRecipientAddress = "a".repeat(1025)
            val exception = assertThrows<RAMFException> {
                StubRAMFMessage(
                    longRecipientAddress,
                    payload,
                    senderCertificate
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
                    recipientAddress,
                    payload,
                    senderCertificate,
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
                recipientAddress,
                payload,
                senderCertificate,
                messageId
            )

            assertEquals(messageId, message.id)
        }

        @Test
        fun `Message id should default to random UUID4 if unset`() {
            val message1 = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate
            )
            val message2 = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate
            )

            UUID.fromString(message1.id)
            UUID.fromString(message2.id)
            assertNotEquals(message1.id, message2.id)
        }

        @Test
        fun `Creation time should be honored if set`() {
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                creationDate = creationDateUtc
            )

            assertEquals(creationDateUtc, message.creationDate)
        }

        @Test
        fun `Creation date should default to current UTC time if unset`() {
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate
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
                    recipientAddress,
                    payload,
                    senderCertificate,
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
                    recipientAddress,
                    payload,
                    senderCertificate,
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
                recipientAddress,
                payload,
                senderCertificate,
                ttl = ttl
            )

            assertEquals(ttl, message.ttl)
        }

        @Test
        fun `TTL should default to 5 minutes if unset`() {
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate
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
                    recipientAddress,
                    longPayload,
                    senderCertificate
                )
            }

            assertEquals(
                "Payload cannot span more than $octetsIn8Mib octets (got $longPayloadLength)",
                exception.message
            )
        }

        @Test
        fun `Sender certificate chain should be honored if set`() {
            val chain = setOf(senderCertificate)
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                senderCertificateChain = chain
            )

            assertEquals(chain, message.senderCertificateChain)
        }

        @Test
        fun `Sender certificate chain should default to an empty set if unset`() {
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate
            )

            assertEquals(0, message.senderCertificateChain.size)
        }
    }

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should be delegated to serializer`() {
            val stubCaCertificate = issueStubCertificate(
                senderKeyPair.public,
                senderKeyPair.private
            )
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                messageId,
                creationDateUtc,
                ttl,
                setOf(stubCaCertificate)
            )

            val serialization = STUB_SERIALIZER.serialize(message, senderKeyPair.private)

            val messageDeserialized = StubRAMFMessage.deserialize(serialization)
            // TODO: Implement RAMFMessage.equals() and use it here
            assertEquals(message.recipientAddress, messageDeserialized.recipientAddress)
            assertEquals(message.id, messageDeserialized.id)
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
                recipientAddress,
                payload,
                senderCertificate
            )

            @Test
            fun `SHA-256 should be used by default`() {
                val cmsSignedDataSerialized =
                    skipFormatSignature(stubMessage.serialize(senderKeyPair.private))

                val cmsSignedData = parseCmsSignedData(cmsSignedDataSerialized)

                assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
                assertEquals(
                    HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA256],
                    cmsSignedData.digestAlgorithmIDs.first().algorithm
                )
            }

            @Test
            fun `Hashing algorithm should be customizable`() {
                val messageSerialized = stubMessage.serialize(
                    senderKeyPair.private,
                    hashingAlgorithm = HashingAlgorithm.SHA384
                )
                val cmsSignedDataSerialized = skipFormatSignature(messageSerialized)

                val cmsSignedData = parseCmsSignedData(cmsSignedDataSerialized)

                assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
                assertEquals(
                    HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA384],
                    cmsSignedData.digestAlgorithmIDs.first().algorithm
                )
            }
        }
    }

    @Nested
    inner class Validate {
        @Test
        fun `Creation date in the future should be refused`() {
            val futureDate = ZonedDateTime.now().plusSeconds(2)
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                creationDate = futureDate
            )

            val exception = assertThrows<RAMFException> { message.validate() }

            assertEquals("Creation date is in the future", exception.message)
        }

        @Test
        fun `Creation date before start date of sender certificate should be refused`() {
            val creationDate = senderCertificate.certificateHolder.notBefore.toInstant()
                .atZone(ZoneId.systemDefault()).minusSeconds(1)
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                creationDate = creationDate
            )

            val exception = assertThrows<RAMFException> { message.validate() }

            assertEquals(
                "Message was created before sender certificate was valid",
                exception.message
            )
        }

        @Test
        fun `Creation date matching start date of sender certificate should be accepted`() {
            val creationDate = senderCertificate.certificateHolder.notBefore.toInstant()
                .atZone(ZoneId.systemDefault())
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                creationDate = creationDate
            )

            message.validate()
        }

        @Test
        fun `Creation date equal to the current date should be accepted`() {
            val message = StubRAMFMessage(recipientAddress, payload, senderCertificate)

            message.validate()
        }

        @Test
        fun `Expiry date in the past should be refused`() {
            val creationDate = senderCertificate.certificateHolder.notBefore.toInstant()
                .atZone(ZoneId.systemDefault())
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                senderCertificate,
                creationDate = creationDate,
                ttl = 0
            )

            val exception = assertThrows<RAMFException> { message.validate() }

            assertEquals("Message already expired", exception.message)
        }

        @Test
        fun `Invalid sender certificates should be refused`() {
            val now = ZonedDateTime.now()
            val expiredCertificate = Certificate.issue(
                "foo",
                senderKeyPair.public,
                senderKeyPair.private,
                now.minusSeconds(1),
                validityStartDate = now.minusSeconds(2)
            )
            val message = StubRAMFMessage(
                recipientAddress,
                payload,
                expiredCertificate,
                creationDate = now
            )

            val exception = assertThrows<RAMFException> { message.validate() }

            assertTrue(exception.cause is CertificateException)
            assertEquals("Invalid sender certificate", exception.message)
        }
    }

    @Test
    fun `expiryDate should be calculated from the creationDate and ttl`() {
        val message = StubRAMFMessage(
            recipientAddress,
            payload,
            senderCertificate,
            creationDate = creationDateUtc,
            ttl = ttl
        )

        assertEquals(creationDateUtc.plusSeconds(ttl.toLong()), message.expiryDate)
    }
}
