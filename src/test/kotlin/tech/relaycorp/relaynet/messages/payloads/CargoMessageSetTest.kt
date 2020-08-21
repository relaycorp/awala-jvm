package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.CERTIFICATE
import tech.relaycorp.relaynet.KEY_PAIR
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.messages.ParcelCollectionAck
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

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
    inner class SerializePlaintext {
        @Test
        fun `An empty array should be serialized as such`() {
            val cargoMessageSet = CargoMessageSet(emptyArray())

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeSequence(serialization)
            assertEquals(0, messages.size)
        }

        @Test
        fun `A one-item array should serialized as such`() {
            val message = "the message".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message))

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeSequence(serialization)
            assertEquals(1, messages.size)
            val messageDer = ASN1Utils.getOctetString(messages.first())
            assertEquals(message.asList(), messageDer.octets.asList())
        }

        @Test
        fun `A multi-item set should serialized as such`() {
            val message1 = "message 1".toByteArray()
            val message2 = "message 1".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message1, message2))

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeSequence(serialization)
            assertEquals(2, messages.size)
            val message1Der = ASN1Utils.getOctetString(messages[0])
            val message2Der = ASN1Utils.getOctetString(messages[1])
            assertEquals(message1.asList(), message1Der.octets.asList())
            assertEquals(message2.asList(), message2Der.octets.asList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Non-DER-encoded values should be refused`() {
            val exception = assertThrows<RAMFException> {
                CargoMessageSet.deserialize("invalid".toByteArray())
            }

            assertEquals("Invalid CargoMessageSet", exception.message)
            assertNotNull(exception.cause)
            assertEquals("Value is not DER-encoded", exception.cause!!.message)
        }

        @Test
        fun `Outer value should be an ASN1 SEQUENCE`() {
            val exception = assertThrows<RAMFException> {
                CargoMessageSet.deserialize(DERVisibleString("invalid").encoded)
            }

            assertEquals("Invalid CargoMessageSet", exception.message)
            assertNotNull(exception.cause)
            assertEquals("Value is not an ASN.1 sequence", exception.cause!!.message)
        }

        @Test
        fun `An empty sequence should be accepted`() {
            val serialization = ASN1Utils.serializeSequence(emptyArray())

            val cargoMessageSet = CargoMessageSet.deserialize(serialization)

            assertEquals(0, cargoMessageSet.messages.size)
        }

        @Test
        fun `A single-item sequence should be accepted`() {
            val message = "the message".toByteArray()
            val serialization =
                ASN1Utils.serializeSequence(arrayOf(DEROctetString(message)), false)

            val cargoMessageSet = CargoMessageSet.deserialize(serialization)

            assertEquals(1, cargoMessageSet.messages.size)
            assertEquals(message.asList(), cargoMessageSet.messages.first().asList())
        }

        @Test
        fun `A multi-item sequence should be accepted`() {
            val message1 = "message 1".toByteArray()
            val message2 = "message 2".toByteArray()
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString(message1),
                    DEROctetString(message2)
                ),
                false
            )

            val cargoMessageSet = CargoMessageSet.deserialize(serialization)

            assertEquals(2, cargoMessageSet.messages.size)
            assertEquals(message1.asList(), cargoMessageSet.messages[0].asList())
            assertEquals(message2.asList(), cargoMessageSet.messages[1].asList())
        }
    }

    @Nested
    inner class ClassifyMessages {
        @Test
        fun `Sequence should be empty if there are no messages`() {
            val cargoMessageSet = CargoMessageSet(emptyArray())

            assertEquals(0, cargoMessageSet.classifyMessages().count())
        }

        @Test
        fun `Encapsulated messages should be wrapped in CargoMessage instances`() {
            val recipientEndpointAddress = "https://foo.relaycorp.tech"
            val parcelSerialized =
                Parcel(recipientEndpointAddress, "".toByteArray(), CERTIFICATE)
                    .serialize(KEY_PAIR.private)
            val pcaSerialized =
                ParcelCollectionAck("0deadbeef", recipientEndpointAddress, "parcel-id")
                    .serialize()
            val cargoMessageSet = CargoMessageSet(arrayOf(parcelSerialized, pcaSerialized))

            val cargoMessages = cargoMessageSet.classifyMessages().asSequence().toList()

            assertEquals(2, cargoMessages.size)
            assertEquals(CargoMessage.Type.PARCEL, cargoMessages[0].type)
            assertEquals(parcelSerialized.asList(), cargoMessages[0].messageSerialized.asList())
            assertEquals(CargoMessage.Type.PCA, cargoMessages[1].type)
            assertEquals(pcaSerialized.asList(), cargoMessages[1].messageSerialized.asList())
        }
    }
}
