package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.ramf.RAMFSerializationTestCase
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class CargoCollectionAuthorizationTest :
    RAMFSerializationTestCase<CargoCollectionAuthorization>(
        ::CargoCollectionAuthorization,
        { r: String, p: ByteArray, s: Certificate -> CargoCollectionAuthorization(r, p, s) },
        0x44,
        0x00,
        CargoCollectionAuthorization.Companion
    )
