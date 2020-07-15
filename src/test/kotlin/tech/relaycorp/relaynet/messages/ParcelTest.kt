package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.ramf.makeRAMFMessageCompanionTests
import tech.relaycorp.relaynet.ramf.makeRAMFMessageConstructorTests
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class ParcelTest {
    @TestFactory
    fun makeConstructorTests() = makeRAMFMessageConstructorTests(
        ::Parcel,
        { r: String, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
        0x50,
        0x00
    )

    @Nested
    inner class Companion {
        @TestFactory
        fun makeDeserializationTests() = makeRAMFMessageCompanionTests(Parcel.Companion, ::Parcel)
    }
}
