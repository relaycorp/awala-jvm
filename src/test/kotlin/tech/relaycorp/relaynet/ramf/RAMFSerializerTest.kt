package tech.relaycorp.relaynet.ramf

import java.nio.charset.Charset
import java.time.LocalDateTime
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

internal val stubRamf = RAMFSerializer(
        32, 0, "04334", "message-id", LocalDateTime.now(), 1, "payload".toByteArray()
)

class RAMFSerializerTest {
    @Nested
    inner class Serialize {
        @Test
        fun `Magic constant should be ASCII string "Relaynet"`() {
            val serialization = stubRamf.serialize()

            val magicSignature = serialization.copyOfRange(0, 8)
            assertEquals("Relaynet", magicSignature.toString(Charset.forName("ASCII")))
        }

        @Test
        fun `Concrete message type should be set`() {
            val serialization = stubRamf.serialize()

            assertEquals(stubRamf.concreteMessageType, serialization[8])
        }

        @Test
        fun `Concrete message version should be set`() {
            val serialization = stubRamf.serialize()

            assertEquals(stubRamf.concreteMessageVersion, serialization[9])
        }

        @Test
        fun `Message fields should be wrapped in an ASN1 Sequence`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val primitive = asn1Stream.readObject()
            val sequence = ASN1Sequence.getInstance(primitive)
            assertEquals(5, sequence.size())
        }

        @Test
        fun `Recipient should be stored as an ASN1 VisibleString`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val sequence = ASN1Sequence.getInstance(asn1Stream.readObject())
            val recipientRaw = sequence.getObjectAt(0) as DLTaggedObject
            val recipientDer = DERVisibleString.getInstance(recipientRaw, false)
            assertEquals(stubRamf.recipient, recipientDer.string)
        }

        @Test
        fun `Message id should be stored as an ASN1 VisibleString`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val sequence = ASN1Sequence.getInstance(asn1Stream.readObject())
            val messageIdRaw = sequence.getObjectAt(1) as DLTaggedObject
            val messageIdDer = DERVisibleString.getInstance(messageIdRaw, false)
            assertEquals(stubRamf.messageId, messageIdDer.string)
        }

        @Test
        fun `Creation time should be stored as an ASN1 DateTime`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val sequence = ASN1Sequence.getInstance(asn1Stream.readObject())
            val creationTimeRaw = sequence.getObjectAt(2) as DLTaggedObject
            // We should technically be using a DateTime type instead of GeneralizedTime, but BC
            // doesn't support it.
            val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
            val dateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")
            assertEquals(
                    stubRamf.creationTimeUtc.format(dateTimeFormatter),
                    creationTimeDer.timeString
            )
        }

        @Test
        fun `TTL should be stored as an ASN1 Integer`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val sequence = ASN1Sequence.getInstance(asn1Stream.readObject())
            val ttlRaw = sequence.getObjectAt(3) as DLTaggedObject
            val ttlDer = ASN1Integer.getInstance(ttlRaw, false)
            assertEquals(stubRamf.ttl, ttlDer.intPositiveValueExact())
        }

        @Test
        fun `Payload should be stored as an ASN1 Octet String`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val sequence = ASN1Sequence.getInstance(asn1Stream.readObject())
            val payloadRaw = sequence.getObjectAt(4) as DLTaggedObject
            val payloadDer = ASN1OctetString.getInstance(payloadRaw, false)
            assertEquals(stubRamf.payload.asList(), payloadDer.octets.asList())
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
