package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.ramf.RAMFSerializationTestCase
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class CargoTest : RAMFSerializationTestCase<Cargo>(
    ::Cargo,
    { r: String, p: ByteArray, s: Certificate -> Cargo(r, p, s) },
    0x43,
    0x00,
    Cargo.Companion
)
