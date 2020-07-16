package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

internal class CargoMessageSetTest {
    @Test
    fun `Messages are accessible from instance`() {
        val message1 = "uno".toByteArray()
        val message2 = "dos".toByteArray()
        val cargoMessageSet = CargoMessageSet(arrayOf(message1, message2))

        assertEquals(
            listOf(message1.asList(), message2.asList()),
            cargoMessageSet.messages.map { it.asList() }
        )
    }

    @Nested
    inner class Serialize {
        @Test
        fun `An empty array should be serialized as such`() {
            val cargoMessageSet = CargoMessageSet(emptyArray())

            val serialization = cargoMessageSet.serialize()

            val messages = deserializeDERSequence(serialization)
            assertEquals(0, messages.size)
        }

        @Test
        fun `A one-item array should serialized as such`() {
            val message = "the message".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message))

            val serialization = cargoMessageSet.serialize()

            val messages = deserializeDERSequence(serialization)
            assertEquals(1, messages.size)
            val messageDer = DEROctetString.getInstance(messages.first() as ASN1TaggedObject, false)
            assertEquals(message.asList(), messageDer.octets.asList())
        }

        @Test
        fun `A multi-item set should serialized as such`() {
            val message1 = "message 1".toByteArray()
            val message2 = "message 1".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message1, message2))

            val serialization = cargoMessageSet.serialize()

            val messages = deserializeDERSequence(serialization)
            assertEquals(2, messages.size)
            val message1Der = DEROctetString.getInstance(messages[0] as ASN1TaggedObject, false)
            val message2Der = DEROctetString.getInstance(messages[1] as ASN1TaggedObject, false)
            assertEquals(message1.asList(), message1Der.octets.asList())
            assertEquals(message2.asList(), message2Der.octets.asList())
        }

        private fun deserializeDERSequence(derSequenceSerialized: ByteArray): Array<ASN1Encodable> {
            val asn1InputStream = ASN1InputStream(derSequenceSerialized)
            val asn1Value = asn1InputStream.readObject()
            val fieldSequence = ASN1Sequence.getInstance(asn1Value)
            return fieldSequence.toArray()
        }
    }
}
