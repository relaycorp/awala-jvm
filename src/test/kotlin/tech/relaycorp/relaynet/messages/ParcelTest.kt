package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.PDACertPath
import tech.relaycorp.relaynet.messages.payloads.ServiceMessage
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import kotlin.test.Test
import kotlin.test.assertEquals

internal class ParcelTest : RAMFSpecializationTestCase<Parcel>(
    ::Parcel,
    { r: String, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
    0x50,
    0x00,
    Parcel.Companion
) {
    @Test
    fun `Payload deserialization should be delegated to ServiceMessage`() {
        val serviceMessage = ServiceMessage("the type", "the content".toByteArray())
        val parcel = Parcel(
            "https://gb.relaycorp.tech",
            serviceMessage.encrypt(PDACertPath.PRIVATE_ENDPOINT),
            PDACertPath.PDA
        )

        val serviceMessageDeserialized = parcel.unwrapPayload(KeyPairSet.PRIVATE_ENDPOINT.private)
        assertEquals(serviceMessage.type, serviceMessageDeserialized.type)
        assertEquals(serviceMessage.content.asList(), serviceMessageDeserialized.content.asList())
    }
}
