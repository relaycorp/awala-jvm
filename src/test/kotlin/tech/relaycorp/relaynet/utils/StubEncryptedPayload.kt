package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload

class StubEncryptedPayload(val payload: String) : EncryptedPayload() {
    override fun serializePlaintext() = payload.toByteArray()
}
