package tech.relaycorp.relaynet.ramf

import java.nio.charset.Charset
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
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
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class RAMFSerializerTest {
    val stubConcreteMessageType: Byte = 32
    val stubConcreteMessageVersion: Byte = 0
    val stubRecipientAddress = "04334"
    val stubMessageId = "message-id"
    val stubCreationTimeUtc: ZonedDateTime = ZonedDateTime.now()
    val stubTtl = 1
    val stubPayload = "payload".toByteArray()

    private val stubSerializer = RAMFSerializer(
        stubConcreteMessageType,
        stubConcreteMessageVersion
    )

    @Nested
    inner class Serialize {
        private val stubFieldSet = RAMFFieldSet(
            stubRecipientAddress,
            stubMessageId,
            stubCreationTimeUtc,
            stubTtl,
            stubPayload
        )
        private val stubSerialization = stubSerializer.serialize(stubFieldSet)

        @Test
        fun `Magic constant should be ASCII string "Relaynet"`() {
            val magicSignature = stubSerialization.copyOfRange(0, 8)
            assertEquals("Relaynet", magicSignature.toString(Charset.forName("ASCII")))
        }

        @Test
        fun `Concrete message type should be set`() {
            assertEquals(stubConcreteMessageType, stubSerialization[8])
        }

        @Test
        fun `Concrete message version should be set`() {
            assertEquals(stubConcreteMessageVersion, stubSerialization[9])
        }

        @Nested
        inner class Fields {
            @Test
            fun `Message fields should be wrapped in an ASN1 Sequence`() {
                val sequence = getAsn1Sequence(stubSerialization)
                assertEquals(5, sequence.size())
            }

            @Test
            fun `Recipient should be stored as an ASN1 VisibleString`() {
                val sequence = getAsn1Sequence(stubSerialization)
                val recipientRaw = sequence.getObjectAt(0) as DLTaggedObject
                val recipientDer = DERVisibleString.getInstance(recipientRaw, false)
                assertEquals(stubFieldSet.recipientAddress, recipientDer.string)
            }

            @Test
            fun `Message id should be stored as an ASN1 VisibleString`() {
                val sequence = getAsn1Sequence(stubSerialization)
                val messageIdRaw = sequence.getObjectAt(1) as DLTaggedObject
                val messageIdDer = DERVisibleString.getInstance(messageIdRaw, false)
                assertEquals(stubFieldSet.messageId, messageIdDer.string)
            }

            @Nested
            inner class CreationTime {
                private val dateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

                @Test
                fun `Creation time should be stored as an ASN1 DateTime`() {
                    val sequence = getAsn1Sequence(stubSerialization)
                    val creationTimeRaw = sequence.getObjectAt(2) as DLTaggedObject
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        stubFieldSet.creationTime.format(dateTimeFormatter),
                        creationTimeDer.timeString
                    )
                }

                @Test
                fun `Creation time should be converted to UTC when provided in different timezone`() {
                    val nowTimezoneUnaware = LocalDateTime.now()
                    val zoneId = ZoneId.of("Etc/GMT-5")
                    val fieldSet = RAMFFieldSet(
                        stubRecipientAddress,
                        stubMessageId,
                        ZonedDateTime.of(nowTimezoneUnaware, zoneId),
                        stubTtl,
                        stubPayload
                    )

                    val sequence = getAsn1Sequence(stubSerializer.serialize(fieldSet))

                    val creationTimeRaw = sequence.getObjectAt(2) as DLTaggedObject
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        fieldSet.creationTime.withZoneSameInstant(ZoneId.of("UTC")).format(dateTimeFormatter),
                        creationTimeDer.timeString
                    )
                }

                @Test
                fun `TTL should be stored as an ASN1 Integer`() {
                    val sequence = getAsn1Sequence(stubSerialization)
                    val ttlRaw = sequence.getObjectAt(3) as DLTaggedObject
                    val ttlDer = ASN1Integer.getInstance(ttlRaw, false)
                    assertEquals(stubFieldSet.ttl, ttlDer.intPositiveValueExact())
                }
            }

            @Test
            fun `Payload should be stored as an ASN1 Octet String`() {
                val sequence = getAsn1Sequence(stubSerialization)
                val payloadRaw = sequence.getObjectAt(4) as DLTaggedObject
                val payloadDer = ASN1OctetString.getInstance(payloadRaw, false)
                assertEquals(stubFieldSet.payload.asList(), payloadDer.octets.asList())
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
        inner class FormatSignature {
            @Test
            fun `Format signature must be present`() {
                val formatSignatureLength = 10
                val invalidSerialization = "a".repeat(formatSignatureLength - 1).toByteArray()

                val exception = assertThrows<RAMFException> { stubSerializer.deserialize(invalidSerialization) }

                assertEquals("Serialization is too short to contain format signature", exception.message)
            }

            @Test
            fun `Magic constant should be ASCII string "Relaynet"`() {
                val incompleteSerialization = "Relaynope01234".toByteArray()

                val exception = assertThrows<RAMFException> { stubSerializer.deserialize(incompleteSerialization) }

                assertEquals("Format signature should start with magic constant 'Relaynet'", exception.message)
            }

            @Test
            @Disabled
            fun `Concrete message type should match expected one`() {
            }

            @Test
            @Disabled
            fun `Concrete message version should match expected one`() {
            }
        }

        @Test
        @Disabled
        fun `Fields should be DER-serialized`() {
        }

        @Test
        @Disabled
        fun `Recipient should be stored as an ASN1 VisibleString`() {
        }

        @Test
        @Disabled
        fun `Message id should be stored as an ASN1 VisibleString`() {
        }

        @Test
        @Disabled
        fun `Creation time should be stored as an ASN1 DateTime`() {
        }

        @Test
        @Disabled
        fun `TTL should be stored as an ASN1 Integer`() {
        }

        @Test
        fun `Payload should be stored as an ASN1 Octet String`() {
        }
    }
}

fun skipFormatSignature(ramfMessage: ByteArray): ByteArray {
    return ramfMessage.copyOfRange(10, ramfMessage.lastIndex + 1)
}
