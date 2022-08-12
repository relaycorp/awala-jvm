package tech.relaycorp.relaynet.ramf

import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.RAMFStubs
import tech.relaycorp.relaynet.utils.StubEncryptedRAMFMessage
import tech.relaycorp.relaynet.utils.assertDateIsAlmostNow
import tech.relaycorp.relaynet.utils.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.cms.parseCmsSignedData
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class RAMFMessageTest {
    private val recipient = RAMFStubs.recipient
    private val messageId = "message-id"
    private val creationDateUtc: ZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC"))
    private val ttl = 1
    private val payload = "payload".toByteArray()

    private val senderKeyPair = KeyPairSet.PDA_GRANTEE
    private val senderCertificate = PDACertPath.PDA

    @Nested
    inner class Constructor {
        @Test
        fun `Message id should not span more than 64 octets`() {
            val longMessageId = "a".repeat(65)
            val exception = assertThrows<RAMFException> {
                StubEncryptedRAMFMessage(
                    recipient,
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
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                messageId
            )

            assertEquals(messageId, message.id)
        }

        @Test
        fun `Message id should default to random UUID4 if unset`() {
            val message1 = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate
            )
            val message2 = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate
            )

            UUID.fromString(message1.id)
            UUID.fromString(message2.id)
            assertNotEquals(message1.id, message2.id)
        }

        @Test
        fun `Creation time should be honored if set`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                creationDate = creationDateUtc
            )

            assertEquals(creationDateUtc, message.creationDate)
        }

        @Test
        fun `Creation date should default to current UTC time if unset`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate
            )

            assertEquals("UTC", message.creationDate.zone.id)
            assertDateIsAlmostNow(message.creationDate)
        }

        @Test
        fun `TTL should not be negative`() {
            val negativeTtl = -1
            val exception = assertThrows<RAMFException> {
                StubEncryptedRAMFMessage(
                    recipient,
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
                StubEncryptedRAMFMessage(
                    recipient,
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
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                ttl = ttl
            )

            assertEquals(ttl, message.ttl)
        }

        @Test
        fun `TTL should default to 5 minutes if unset`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate
            )

            val secondsIn5Min = 5 * 60
            assertEquals(secondsIn5Min, message.ttl)
        }

        @Test
        fun `Payload should not span more than 8 MiB`() {
            val longPayloadLength = RAMFMessage.MAX_PAYLOAD_LENGTH + 1
            val longPayload = "a".repeat(longPayloadLength).toByteArray()
            val exception = assertThrows<RAMFException> {
                StubEncryptedRAMFMessage(
                    recipient,
                    longPayload,
                    senderCertificate
                )
            }

            assertEquals(
                "Payload cannot span more than ${RAMFMessage.MAX_PAYLOAD_LENGTH} octets " +
                    "(got $longPayloadLength)",
                exception.message
            )
        }

        @Test
        fun `Sender certificate chain should be honored if set`() {
            val chain = setOf(senderCertificate)
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                senderCertificateChain = chain
            )

            assertEquals(chain, message.senderCertificateChain)
        }

        @Test
        fun `Sender certificate chain should default to an empty set if unset`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
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
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                messageId,
                creationDateUtc,
                ttl,
                setOf(stubCaCertificate)
            )

            val serialization =
                StubEncryptedRAMFMessage.SERIALIZER.serialize(message, senderKeyPair.private)

            val messageDeserialized = StubEncryptedRAMFMessage.deserialize(serialization)
            // TODO: Implement RAMFMessage.equals() and use it here
            assertEquals(message.recipient, messageDeserialized.recipient)
            assertEquals(message.id, messageDeserialized.id)
            assertEquals(
                message.creationDate.withNano(0).withZoneSameLocal(ZoneId.of("UTC")),
                messageDeserialized.creationDate
            )
            assertEquals(message.ttl, messageDeserialized.ttl)
            assertEquals(message.payload.asList(), messageDeserialized.payload.asList())
            assertEquals(message.senderCertificate, messageDeserialized.senderCertificate)
            assertEquals(
                message.senderCertificateChain,
                messageDeserialized.senderCertificateChain
            )
        }

        @Nested
        inner class Hashing {
            private val stubMessage = StubEncryptedRAMFMessage(
                recipient,
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

    @Test
    fun `getSenderCertificationPath should return certification path`() {
        val message = StubEncryptedRAMFMessage(
            recipient,
            payload,
            PDACertPath.PRIVATE_ENDPOINT,
            senderCertificateChain = setOf(PDACertPath.PRIVATE_GW)
        )

        val certificationPath =
            message.getSenderCertificationPath(setOf(PDACertPath.INTERNET_GW))

        assertEquals(
            listOf(
                PDACertPath.PRIVATE_ENDPOINT,
                PDACertPath.PRIVATE_GW,
                PDACertPath.INTERNET_GW
            ),
            certificationPath.asList()
        )
    }

    @Nested
    inner class RecipientCertificate {
        private val recipientCertificate = PDACertPath.PRIVATE_ENDPOINT

        @Test
        fun `Null should be returned if sender's issuer does not match recipient`() {
            val message = StubEncryptedRAMFMessage(
                recipient.copy(id = "${recipient.id}123"),
                payload,
                senderCertificate,
                senderCertificateChain = setOf(recipientCertificate)
            )

            assertNull(message.recipientCertificate)
        }

        @Test
        fun `Null should be returned if recipient certificate is not attached`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
            )

            assertNull(message.recipientCertificate)
        }

        @Test
        fun `Null should be returned if recipient does not match issuer of sender`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                senderCertificateChain = setOf(
                    PDACertPath.PRIVATE_GW // Wrong
                )
            )

            assertNull(message.recipientCertificate)
        }

        @Test
        fun `Certificate should be returned if it matches message recipient and sender issuer`() {
            val message = StubEncryptedRAMFMessage(
                recipient,
                payload,
                senderCertificate,
                senderCertificateChain = setOf(recipientCertificate)
            )

            assertEquals(recipientCertificate, message.recipientCertificate)
        }
    }

    @Nested
    inner class Validate {
        @Nested
        inner class ValidityPeriod {
            @Test
            fun `Creation date in the future should be refused`() {
                val futureDate = ZonedDateTime.now().plusSeconds(2)
                val message = StubEncryptedRAMFMessage(
                    recipient,
                    payload,
                    senderCertificate,
                    creationDate = futureDate
                )

                val exception = assertThrows<RAMFException> { message.validate() }

                assertEquals("Creation date is in the future", exception.message)
            }

            @Test
            fun `Creation date matching start date of sender certificate should be accepted`() {
                val creationDate = senderCertificate.certificateHolder.notBefore.toInstant()
                    .atZone(ZoneId.systemDefault())
                val message = StubEncryptedRAMFMessage(
                    recipient,
                    payload,
                    senderCertificate,
                    creationDate = creationDate
                )

                message.validate()
            }

            @Test
            fun `Creation date equal to the current date should be accepted`() {
                val message = StubEncryptedRAMFMessage(recipient, payload, senderCertificate)

                message.validate()
            }

            @Test
            fun `Expiry date equal to the current date should be accepted`() {
                val now = ZonedDateTime.now()
                val certificate = Certificate.issue(
                    "the subject for the stub cert",
                    senderKeyPair.public,
                    senderKeyPair.private,
                    now.plusMinutes(1),
                    validityStartDate = now.minusMinutes(1)
                )
                val message = StubEncryptedRAMFMessage(
                    recipient,
                    payload,
                    certificate,
                    creationDate = now.minusNanos(500_000),
                    ttl = 1
                )

                message.validate()
            }

            @Test
            fun `Expiry date in the past should be refused`() {
                val creationDate = senderCertificate.certificateHolder.notBefore.toInstant()
                    .atZone(ZoneId.systemDefault())
                val message = StubEncryptedRAMFMessage(
                    recipient,
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
                val message = StubEncryptedRAMFMessage(
                    recipient,
                    payload,
                    expiredCertificate,
                    creationDate = now
                )

                val exception = assertThrows<RAMFException> { message.validate() }

                assertTrue(exception.cause is CertificateException)
                assertEquals("Invalid sender certificate", exception.message)
            }
        }

        @Nested
        inner class Authorization {
            @Test
            fun `Message should be refused if sender is authorized but not trusted`() {
                val untrustedRecipientKeyPair = generateRSAKeyPair()
                val untrustedRecipientCert = issueStubCertificate(
                    untrustedRecipientKeyPair.public,
                    untrustedRecipientKeyPair.private,
                    isCA = true
                )
                val untrustedSenderKeyPair = generateRSAKeyPair()
                val untrustedSenderCert = issueStubCertificate(
                    untrustedSenderKeyPair.public,
                    untrustedRecipientKeyPair.private,
                    untrustedRecipientCert
                )
                val message = StubEncryptedRAMFMessage(
                    Recipient(untrustedRecipientCert.subjectId),
                    payload,
                    untrustedSenderCert
                )

                val exception = assertThrows<InvalidMessageException> {
                    message.validate(setOf(PDACertPath.INTERNET_GW))
                }

                assertEquals("Sender is not trusted", exception.message)
                assertTrue(exception.cause is CertificateException)
            }

            @Test
            fun `Message should be accepted if sender is trusted`() {
                val message = StubEncryptedRAMFMessage(
                    Recipient(PDACertPath.PRIVATE_ENDPOINT.subjectId),
                    payload,
                    PDACertPath.PDA,
                    senderCertificateChain = setOf(
                        PDACertPath.PRIVATE_GW,
                        PDACertPath.PRIVATE_ENDPOINT
                    )
                )

                message.validate(setOf(PDACertPath.INTERNET_GW))
            }

            @Test
            fun `Message should be refused if recipient doesn't match sender issuer`() {
                val anotherRecipientKeyPair = generateRSAKeyPair()
                val anotherRecipientCert = issueStubCertificate(
                    anotherRecipientKeyPair.public,
                    anotherRecipientKeyPair.private
                )
                val message = StubEncryptedRAMFMessage(
                    Recipient(anotherRecipientCert.subjectId),
                    payload,
                    PDACertPath.PRIVATE_ENDPOINT,
                    senderCertificateChain = setOf(PDACertPath.PRIVATE_GW)
                )

                val exception = assertThrows<InvalidMessageException> {
                    message.validate(setOf(PDACertPath.INTERNET_GW))
                }

                assertEquals("Sender is authorized by the wrong recipient", exception.message)
            }

            @Test
            fun `Authorization enforcement should be skipped if trusted certs are absent`() {
                val untrustedSenderKeyPair = generateRSAKeyPair()
                val untrustedSenderCert = issueStubCertificate(
                    untrustedSenderKeyPair.public,
                    untrustedSenderKeyPair.private
                )
                val message = StubEncryptedRAMFMessage(
                    Recipient(PDACertPath.PRIVATE_ENDPOINT.subjectId),
                    payload,
                    untrustedSenderCert
                )

                message.validate()
            }
        }
    }

    @Test
    fun `expiryDate should be calculated from the creationDate and ttl`() {
        val message = StubEncryptedRAMFMessage(
            recipient,
            payload,
            senderCertificate,
            creationDate = creationDateUtc,
            ttl = ttl
        )

        assertEquals(creationDateUtc.plusSeconds(ttl.toLong()), message.expiryDate)
    }
}
