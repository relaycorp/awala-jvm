package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.ramf.makeRAMFMessageCompanionTests
import tech.relaycorp.relaynet.ramf.makeRAMFMessageConstructorTests

class CargoCollectionAuthorizationTest {
    @TestFactory
    fun makeConstructorTests() =
        makeRAMFMessageConstructorTests(::CargoCollectionAuthorization, 0x51, 0x00)

    @Nested
    inner class Companion {
        @TestFactory
        fun makeDeserializationTests() = makeRAMFMessageCompanionTests(
            CargoCollectionAuthorization.Companion,
            ::CargoCollectionAuthorization
        )
    }
}
