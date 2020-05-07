package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.ramf.makeRAMFMessageCompanionTests
import tech.relaycorp.relaynet.ramf.makeRAMFMessageConstructorTests
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CargoTest {
    @TestFactory
    fun makeConstructorTests() = makeRAMFMessageConstructorTests(
        ::Cargo,
        { r: String, p: ByteArray, s: Certificate -> Cargo(r, p, s) },
        0x43,
        0x00
    )

    @Nested
    inner class Companion {
        @TestFactory
        fun makeDeserializationTests() = makeRAMFMessageCompanionTests(Cargo.Companion, ::Cargo)
    }
}
