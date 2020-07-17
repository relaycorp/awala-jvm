package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.ramf.RAMFSerializationTestCase
import tech.relaycorp.relaynet.wrappers.x509.Certificate

internal class ParcelTest : RAMFSerializationTestCase<Parcel>(
    ::Parcel,
    { r: String, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
    0x50,
    0x00,
    Parcel.Companion
)
