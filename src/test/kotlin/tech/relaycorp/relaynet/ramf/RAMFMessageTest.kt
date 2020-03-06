package tech.relaycorp.relaynet.ramf

import java.nio.charset.Charset
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.test.Test
import kotlin.test.assertEquals
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.DLTaggedObject
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows

class RAMFMessageTest {
    val stubConcreteMessageType: Byte = 32
    val stubConcreteMessageVersion: Byte = 0
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
                RAMFMessage(
                    stubConcreteMessageType,
                    stubConcreteMessageVersion,
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
                RAMFMessage(
                    stubConcreteMessageType,
                    stubConcreteMessageVersion,
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
                RAMFMessage(
                    stubConcreteMessageType,
                    stubConcreteMessageVersion,
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
                RAMFMessage(
                    stubConcreteMessageType,
                    stubConcreteMessageVersion,
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
                RAMFMessage(
                    stubConcreteMessageType,
                    stubConcreteMessageVersion,
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
        private val stubRamfMessage = RAMFMessage(
            stubConcreteMessageType,
            stubConcreteMessageVersion,
            stubRecipientAddress,
            stubMessageId,
            stubCreationTimeUtc,
            stubTtl,
            stubPayload
        )
        private val stubRamfSerialization = stubRamfMessage.serialize()

        @Test
        fun `Magic constant should be ASCII string "Relaynet"`() {
            val magicSignature = stubRamfSerialization.copyOfRange(0, 8)
            assertEquals("Relaynet", magicSignature.toString(Charset.forName("ASCII")))
        }

        @Test
        fun `Concrete message type should be set`() {
            assertEquals(stubRamfMessage.concreteMessageType, stubRamfSerialization[8])
        }

        @Test
        fun `Concrete message version should be set`() {
            assertEquals(stubRamfMessage.concreteMessageVersion, stubRamfSerialization[9])
        }

        @Nested
        inner class Fields {
            @Test
            fun `Message fields should be wrapped in an ASN1 Sequence`() {
                val sequence = getAsn1Sequence(stubRamfSerialization)
                assertEquals(5, sequence.size())
            }

            @Test
            fun `Recipient should be stored as an ASN1 VisibleString`() {
                val sequence = getAsn1Sequence(stubRamfSerialization)
                val recipientRaw = sequence.getObjectAt(0) as DLTaggedObject
                val recipientDer = DERVisibleString.getInstance(recipientRaw, false)
                assertEquals(stubRamfMessage.recipientAddress, recipientDer.string)
            }

            @Test
            fun `Message id should be stored as an ASN1 VisibleString`() {
                val sequence = getAsn1Sequence(stubRamfSerialization)
                val messageIdRaw = sequence.getObjectAt(1) as DLTaggedObject
                val messageIdDer = DERVisibleString.getInstance(messageIdRaw, false)
                assertEquals(stubRamfMessage.messageId, messageIdDer.string)
            }

            @Nested
            inner class CreationTime {
                private val dateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

                @Test
                fun `Creation time should be stored as an ASN1 DateTime`() {
                    val sequence = getAsn1Sequence(stubRamfSerialization)
                    val creationTimeRaw = sequence.getObjectAt(2) as DLTaggedObject
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        stubRamfMessage.creationTime.format(dateTimeFormatter),
                        creationTimeDer.timeString
                    )
                }

                @Test
                fun `Creation time should be converted to UTC when provided in different timezone`() {
                    val nowTimezoneUnaware = LocalDateTime.now()
                    val zoneId = ZoneId.of("Etc/GMT-5")
                    val message = RAMFMessage(
                        stubConcreteMessageType,
                        stubConcreteMessageVersion,
                        stubRecipientAddress,
                        stubMessageId,
                        ZonedDateTime.of(nowTimezoneUnaware, zoneId),
                        stubTtl,
                        stubPayload
                    )

                    val sequence = getAsn1Sequence(message.serialize())

                    val creationTimeRaw = sequence.getObjectAt(2) as DLTaggedObject
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        message.creationTime.withZoneSameInstant(ZoneId.of("UTC")).format(dateTimeFormatter),
                        creationTimeDer.timeString
                    )
                }

                @Test
                fun `TTL should be stored as an ASN1 Integer`() {
                    val sequence = getAsn1Sequence(stubRamfSerialization)
                    val ttlRaw = sequence.getObjectAt(3) as DLTaggedObject
                    val ttlDer = ASN1Integer.getInstance(ttlRaw, false)
                    assertEquals(stubRamfMessage.ttl, ttlDer.intPositiveValueExact())
                }
            }

            @Test
            fun `Payload should be stored as an ASN1 Octet String`() {
                val sequence = getAsn1Sequence(stubRamfSerialization)
                val payloadRaw = sequence.getObjectAt(4) as DLTaggedObject
                val payloadDer = ASN1OctetString.getInstance(payloadRaw, false)
                assertEquals(stubRamfMessage.payload.asList(), payloadDer.octets.asList())
            }

            private fun getAsn1Sequence(serialization: ByteArray): ASN1Sequence {
                val asn1Serialization = skipFormatSignature(serialization)
                val asn1Stream = ASN1InputStream(asn1Serialization)
                return ASN1Sequence.getInstance(asn1Stream.readObject())
            }
        }
    }

    @Nested
    inner class Deserialize {
        @Nested
        inner class CreationTime {
            @Test
            @Disabled("Pending implementation")
            fun `A timezone other than UTC should not be allowed`() {
            }

            @Test
            @Disabled("Pending implementation")
            fun `Timezone may be unset`() {
            }

            @Test
            @Disabled("Pending implementation")
            fun `Timezone may be set to UTC`() {
            }
        }
    }
}

fun skipFormatSignature(ramfMessage: ByteArray): ByteArray {
    return ramfMessage.copyOfRange(10, ramfMessage.lastIndex + 1)
}
