package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.ramf.makeRAMFMessageCompanionTests
import tech.relaycorp.relaynet.ramf.makeRAMFMessageConstructorTests

class CargoTest {
    @TestFactory
    fun makeConstructorTests() = makeRAMFMessageConstructorTests(::Cargo, 0x43, 0x00)

    @Nested
    inner class Companion {
        @TestFactory
        fun makeDeserializationTests() = makeRAMFMessageCompanionTests(Cargo.Companion, ::Cargo)
    }
}
