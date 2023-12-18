package tech.relaycorp.relaynet

import kotlin.test.Test
import kotlin.test.assertEquals

class CargoDeliveryRequestTest {
    @Test
    fun `Fields should be set`() {
        val localId = "id"
        val cargoSerialized = "cargo"

        val request = CargoDeliveryRequest(localId) { cargoSerialized.byteInputStream() }

        assertEquals(localId, request.localId)
        assertEquals(
            cargoSerialized,
            request.cargoSerialized().bufferedReader().use { it.readText() },
        )
    }
}
