package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.CERTIFICATE
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import kotlin.test.Test

internal class ParcelTest : RAMFSpecializationTestCase<Parcel>(
    ::Parcel,
    { r: String, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
    0x50,
    0x00,
    Parcel.Companion
) {
    @Test
    fun `Payload deserialization should be delegated to ServiceMessage`() {
        val parcel = Parcel("https://gb.relaycorp.tech", "".toByteArray(), CERTIFICATE)

        // TODO
        assertThrows<NotImplementedError> { parcel.deserializePayload("invalid".toByteArray()) }
    }
}
