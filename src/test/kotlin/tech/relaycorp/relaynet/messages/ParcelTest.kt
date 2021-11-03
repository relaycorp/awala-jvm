package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.messages.payloads.ServiceMessage
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class ParcelTest : RAMFSpecializationTestCase<Parcel>(
    ::Parcel,
    { r: String, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
    0x50,
    0x00,
    Parcel.Companion
) {
    private val recipientSessionKeyPair = SessionKey.generate()
    private val senderSessionKeyPair = SessionKey.generate()

    @Test
    fun `Payload deserialization should be delegated to ServiceMessage`() {
        val serviceMessage = ServiceMessage("the type", "the content".toByteArray())
        val parcel = Parcel(
            "https://gb.relaycorp.tech",
            serviceMessage.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
            PDACertPath.PDA
        )

        val serviceMessageDeserialized = parcel.unwrapPayload(recipientSessionKeyPair.privateKey)
        assertEquals(serviceMessage.type, serviceMessageDeserialized.type)
        assertEquals(serviceMessage.content.asList(), serviceMessageDeserialized.content.asList())
    }
}
