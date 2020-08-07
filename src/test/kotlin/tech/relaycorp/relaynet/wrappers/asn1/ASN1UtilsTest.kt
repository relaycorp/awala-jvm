package tech.relaycorp.relaynet.wrappers.asn1

import org.bouncycastle.asn1.ASN1StreamParser
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTaggedObjectParser
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DEROctetStringParser
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.DLSequenceParser
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal class ASN1UtilsTest {
    val value1 = DERVisibleString("foo")
    val value2 = DEROctetString("bar".toByteArray())

    @Nested
    inner class SerializeSequence {
        @Test
        fun `Values should be explicitly tagged by default`() {
            val serialization = ASN1Utils.serializeSequence(arrayOf(value1, value2))

            val parser = ASN1StreamParser(serialization)
            val sequence = parser.readObject() as DLSequenceParser

            val item1 = sequence.readObject()
            assertTrue(item1 is DERVisibleString)
            assertEquals(value1.string, item1.string)

            val item2 = sequence.readObject()
            assertTrue(item2 is DEROctetStringParser)
            assertEquals(
                value2.octets.asList(),
                (item2.loadedObject as DEROctetString).octets.asList()
            )
        }

        @Test
        fun `Implicitly-tagged values should be supported`() {
            val serialization = ASN1Utils.serializeSequence(arrayOf(value1, value2), false)

            val parser = ASN1StreamParser(serialization)
            val sequence = parser.readObject() as DLSequenceParser

            val item1 = DERVisibleString.getInstance(
                ((sequence.readObject() as BERTaggedObjectParser).loadedObject as ASN1TaggedObject),
                false
            )
            assertEquals(value1.string, item1.string)

            val item2 = DEROctetString.getInstance(
                ((sequence.readObject() as BERTaggedObjectParser).loadedObject as ASN1TaggedObject),
                false
            )
            assertEquals(
                value2.octets.asList(),
                (item2.loadedObject as DEROctetString).octets.asList()
            )
        }
    }

    @Nested
    inner class DeserializeSequence {
        @Test
        fun `Value should be refused if it's empty`() {
            val exception =
                assertThrows<ASN1Exception> { ASN1Utils.deserializeSequence(byteArrayOf()) }

            assertEquals("Value is empty", exception.message)
        }

        @Test
        fun `Value should be refused if it's not DER-encoded`() {
            val exception =
                assertThrows<ASN1Exception> { ASN1Utils.deserializeSequence("a".toByteArray()) }

            assertEquals("Value is not DER-encoded", exception.message)
        }

        @Test
        fun `Value should be refused if it's not a sequence`() {
            val serialization = DERVisibleString("hey").encoded

            val exception =
                assertThrows<ASN1Exception> { ASN1Utils.deserializeSequence(serialization) }

            assertEquals("Value is not an ASN.1 sequence", exception.message)
        }

        @Test
        fun `Valid sequences should be deserialized`() {
            val serialization = ASN1Utils.serializeSequence(arrayOf(value1, value2))

            val sequence = ASN1Utils.deserializeSequence(serialization)

            assertEquals(2, sequence.size)
            assertTrue(sequence[0] is DERVisibleString)
            assertEquals(value1.octets.asList(), (sequence[0] as DERVisibleString).octets.asList())
            assertTrue(sequence[1] is DEROctetString)
            assertEquals(value2.octets.asList(), (sequence[1] as DEROctetString).octets.asList())
        }
    }
}
