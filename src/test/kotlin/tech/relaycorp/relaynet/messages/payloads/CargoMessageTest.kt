package tech.relaycorp.relaynet.messages.payloads

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.CERTIFICATE
import tech.relaycorp.relaynet.KEY_PAIR
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.messages.ParcelCollectionAck

class CargoMessageTest {
    @Nested
    inner class Constructor {
        private val recipientEndpointAddress = "https://foo.relaycorp.tech"

        @Test
        fun `Parcels should be correctly classified as such`() {
            val parcel = Parcel(recipientEndpointAddress, "".toByteArray(), CERTIFICATE)
            val parcelSerialized = parcel.serialize(KEY_PAIR.private)

            val cargoMessage = CargoMessage(parcelSerialized)

            assertEquals(CargoMessage.Type.PARCEL, cargoMessage.type)
        }

        @Test
        fun `PCAs should be correctly classified as such`() {
            val pca = ParcelCollectionAck("0deadbeef", recipientEndpointAddress, "parcel-id")
            val pcaSerialized = pca.serialize()

            val cargoMessage = CargoMessage(pcaSerialized)

            assertEquals(CargoMessage.Type.PCA, cargoMessage.type)
        }

        @Test
        fun `Messages too short to contain format signature should not be assigned a type`() {
            val cargoMessage = CargoMessage("RelaynetP".toByteArray())

            assertNull(cargoMessage.type)
        }

        @Test
        fun `Invalid messages should not be assigned a type`() {
            val cargoMessage = CargoMessage("RelaynetyP0".toByteArray())

            assertNull(cargoMessage.type)
        }
    }
}
