package tech.relaycorp.relaynet.messages.control

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.DERNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class ParcelDeliveryTest {
    val deliveryId = "the id"
    val parcelSerialized = "This appears to be a parcel".toByteArray()

    @Nested
    inner class Serialize {
        @Test
        fun `Delivery id should be serialized`() {
            val delivery = ParcelDelivery(deliveryId, parcelSerialized)

            val serialization = delivery.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val deliveryIdASN1 = ASN1Utils.getVisibleString(sequenceASN1.first())
            assertEquals(deliveryId, deliveryIdASN1.string)
        }

        @Test
        fun `Parcel should be serialized`() {
            val delivery = ParcelDelivery(deliveryId, parcelSerialized)

            val serialization = delivery.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val parcelSerializedASN1 = ASN1Utils.getOctetString(sequenceASN1[1])
            assertEquals(
                parcelSerialized.asList(),
                parcelSerializedASN1.octets.asList(),
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be a DER sequence`() {
            val exception =
                assertThrows<InvalidMessageException> {
                    ParcelDelivery.deserialize(byteArrayOf(0))
                }

            assertEquals("Delivery is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least two items`() {
            val invalidSequence = ASN1Utils.serializeSequence(listOf(DERNull.INSTANCE), false)

            val exception =
                assertThrows<InvalidMessageException> {
                    ParcelDelivery.deserialize(invalidSequence)
                }

            assertEquals(
                "Delivery sequence should have at least 2 items (got 1)",
                exception.message,
            )
        }

        @Test
        fun `Valid deliveries should be accepted`() {
            val delivery = ParcelDelivery(deliveryId, parcelSerialized)
            val serialization = delivery.serialize()

            val deliveryDeserialized = ParcelDelivery.deserialize(serialization)

            assertEquals(deliveryId, deliveryDeserialized.deliveryId)
            assertEquals(parcelSerialized.asList(), deliveryDeserialized.parcelSerialized.asList())
        }
    }
}
