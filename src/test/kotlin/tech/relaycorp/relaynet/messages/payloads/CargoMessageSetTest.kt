package tech.relaycorp.relaynet.messages.payloads

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.messages.ParcelCollectionAck
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.ramf.InvalidPayloadException
import tech.relaycorp.relaynet.utils.ID_CERTIFICATE
import tech.relaycorp.relaynet.utils.ID_KEY_PAIR
import tech.relaycorp.relaynet.utils.RAMFStubs
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

internal class CargoMessageSetTest {
    @Test
    fun `Messages should be accessible from instance`() {
        val message1 = "uno".toByteArray()
        val message2 = "dos".toByteArray()
        val cargoMessageSet = CargoMessageSet(arrayOf(message1, message2))

        assertEquals(
            listOf(message1.asList(), message2.asList()),
            cargoMessageSet.messages.map { it.asList() },
        )
    }

    @Nested
    inner class SerializePlaintext {
        @Test
        fun `An empty array should be serialized as such`() {
            val cargoMessageSet = CargoMessageSet(emptyArray())

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeHomogeneousSequence<DEROctetString>(serialization)
            assertEquals(0, messages.size)
        }

        @Test
        fun `A one-item array should serialized as such`() {
            val message = "the message".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message))

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeHomogeneousSequence<DEROctetString>(serialization)
            assertEquals(1, messages.size)
            assertEquals(message.asList(), messages.first().octets.asList())
        }

        @Test
        fun `A multi-item set should serialized as such`() {
            val message1 = "message 1".toByteArray()
            val message2 = "message 1".toByteArray()
            val cargoMessageSet = CargoMessageSet(arrayOf(message1, message2))

            val serialization = cargoMessageSet.serializePlaintext()

            val messages = ASN1Utils.deserializeHomogeneousSequence<DEROctetString>(serialization)
            assertEquals(2, messages.size)
            assertEquals(message1.asList(), messages[0].octets.asList())
            assertEquals(message2.asList(), messages[1].octets.asList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Non-DER-encoded values should be refused`() {
            val exception =
                assertThrows<InvalidPayloadException> {
                    CargoMessageSet.deserialize("invalid".toByteArray())
                }

            assertEquals("Invalid CargoMessageSet", exception.message)
            assertNotNull(exception.cause)
            assertEquals("Value is not DER-encoded", exception.cause!!.message)
        }

        @Test
        fun `Outer value should be an ASN1 SEQUENCE`() {
            val exception =
                assertThrows<InvalidPayloadException> {
                    CargoMessageSet.deserialize(DERVisibleString("invalid").encoded)
                }

            assertEquals("Invalid CargoMessageSet", exception.message)
            assertNotNull(exception.cause)
            assertEquals("Value is not an ASN.1 sequence", exception.cause!!.message)
        }

        @Test
        fun `An empty sequence should be accepted`() {
            val serialization = ASN1Utils.serializeSequence(listOf())

            val cargoMessageSet = CargoMessageSet.deserialize(serialization)

            assertEquals(0, cargoMessageSet.messages.size)
        }

        @Test
        fun `A single-item sequence should be accepted`() {
            val message = "the message".toByteArray()
            val cms = CargoMessageSet(arrayOf(message))
            val serialization = cms.serializePlaintext()

            val cmsDeserialized = CargoMessageSet.deserialize(serialization)

            assertEquals(1, cmsDeserialized.messages.size)
            assertEquals(message.asList(), cmsDeserialized.messages.first().asList())
        }

        @Test
        fun `A multi-item sequence should be accepted`() {
            val message1 = "message 1".toByteArray()
            val message2 = "message 2".toByteArray()
            val cms = CargoMessageSet(arrayOf(message1, message2))
            val serialization = cms.serializePlaintext()

            val cmsDeserialized = CargoMessageSet.deserialize(serialization)

            assertEquals(2, cmsDeserialized.messages.size)
            assertEquals(message1.asList(), cmsDeserialized.messages[0].asList())
            assertEquals(message2.asList(), cmsDeserialized.messages[1].asList())
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
            val parcelSerialized =
                Parcel(Recipient(RAMFStubs.recipientId), "".toByteArray(), ID_CERTIFICATE)
                    .serialize(ID_KEY_PAIR.private)
            val pcaSerialized =
                ParcelCollectionAck("0deadbeef", "0deadc0de", "parcel-id")
                    .serialize()
            val cargoMessageSet = CargoMessageSet(arrayOf(parcelSerialized, pcaSerialized))

            val cargoMessages = cargoMessageSet.classifyMessages().toList()

            assertEquals(2, cargoMessages.size)
            assertEquals(CargoMessage.Type.PARCEL, cargoMessages[0].type)
            assertContentEquals(parcelSerialized, cargoMessages[0].messageSerialized)
            assertEquals(CargoMessage.Type.PCA, cargoMessages[1].type)
            assertContentEquals(pcaSerialized, cargoMessages[1].messageSerialized)
        }
    }
}
