package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.ramf.makeRAMFMessageCompanionTests
import tech.relaycorp.relaynet.ramf.makeRAMFMessageConstructorTests
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CargoCollectionAuthorizationTest {
    @TestFactory
    fun makeConstructorTests() =
        makeRAMFMessageConstructorTests(
            ::CargoCollectionAuthorization,
            { r: String, p: ByteArray, s: Certificate -> CargoCollectionAuthorization(r, p, s) },
            0x51,
            0x00
        )

    @Nested
    inner class Companion {
        @TestFactory
        fun makeDeserializationTests() = makeRAMFMessageCompanionTests(
            CargoCollectionAuthorization.Companion,
            ::CargoCollectionAuthorization
        )
    }
}
