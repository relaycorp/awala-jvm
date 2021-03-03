package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DERNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

const val TYPE = "this is the type"
val CONTENT = "this is the content".toByteArray()

internal class ServiceMessageTest {
    @Nested
    inner class SerializePlaintext {
        @Test
        fun `Type should be serialized`() {
            val message = ServiceMessage(TYPE, CONTENT)

            val serialization = message.serializePlaintext()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val typeASN1 = ASN1Utils.getVisibleString(sequence.first())
            assertEquals(TYPE, typeASN1.string)
        }

        @Test
        fun `Content should be serialized`() {
            val message = ServiceMessage(TYPE, CONTENT)

            val serialization = message.serializePlaintext()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val contentASN1 = ASN1Utils.getOctetString(sequence[1])
            assertEquals(CONTENT.asList(), contentASN1.octets.asList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be DER sequence`() {
            val invalidSerialization = "foo".toByteArray()

            val exception = assertThrows<InvalidMessageException> {
                ServiceMessage.deserialize(invalidSerialization)
            }

            assertEquals("Service message is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least two items`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                ServiceMessage.deserialize(invalidSerialization)
            }

            assertEquals(
                "Service message sequence should have at least two items (got 1)",
                exception.message
            )
        }

        @Test
        fun `Valid service message should be accepted`() {
            val message = ServiceMessage(TYPE, CONTENT)
            val serialization = message.serializePlaintext()

            val messageDeserialized = ServiceMessage.deserialize(serialization)

            assertEquals(TYPE, messageDeserialized.type)
            assertEquals(CONTENT.asList(), messageDeserialized.content.asList())
        }
    }
}
