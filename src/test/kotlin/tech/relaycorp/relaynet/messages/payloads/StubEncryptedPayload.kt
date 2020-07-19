package tech.relaycorp.relaynet.messages.payloads

class StubEncryptedPayload(val payload: String) : EncryptedPayload() {
    override fun serializePlaintext() = payload.toByteArray()
}
