package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.messages.payloads.PayloadPlaintext

class StubPayload(val payload: String) : PayloadPlaintext {
    override fun serialize() = payload.toByteArray()
}
