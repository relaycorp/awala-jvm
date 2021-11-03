package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.utils.ID_CERTIFICATE
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class CargoCollectionAuthorizationTest :
    RAMFSpecializationTestCase<CargoCollectionAuthorization>(
        ::CargoCollectionAuthorization,
        { r: String, p: ByteArray, s: Certificate -> CargoCollectionAuthorization(r, p, s) },
        0x44,
        0x00,
        CargoCollectionAuthorization.Companion
    ) {
    @Test
    fun `Payload deserialization should be delegated to EmptyPayload`() {
        val cca = CargoCollectionAuthorization(
            "https://gb.relaycorp.tech", "".toByteArray(), ID_CERTIFICATE
        )

        cca.deserializePayload()
    }
}
