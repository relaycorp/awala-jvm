package tech.relaycorp.relaynet.ramf

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.util.ASN1Dump
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestInstance
import java.nio.charset.Charset
import java.time.LocalDateTime
import kotlin.test.Test
import kotlin.test.assertEquals

internal val stubRamf = RAMFSerializer(
        32, 0, "04334", "message-id", LocalDateTime.now(), 1, "payload".toByteArray()
)

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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
            assertEquals(sequence.size(), 5)
        }

        @Test
        fun `Recipient should be stored as an ASN1 VisibleString`() {
            val asn1Serialization = skipFormatSignature(stubRamf.serialize())

            val asn1Stream = ASN1InputStream(asn1Serialization)
            val primitive = asn1Stream.readObject()
            val sequence = ASN1Sequence.getInstance(primitive)
            val recipientRaw = sequence.getObjectAt(0) as ASN1TaggedObject
            println(ASN1Dump.dumpAsString(recipientRaw))
            assertEquals(recipientRaw.isExplicit, false)
            assertEquals(recipientRaw.tagNo, 0)
            assertEquals(recipientRaw.encoded.toString(), stubRamf.recipient)
        }
    }
}

fun skipFormatSignature(ramfMessage: ByteArray): ByteArray {
    return ramfMessage.copyOfRange(10, ramfMessage.lastIndex + 1)
}
