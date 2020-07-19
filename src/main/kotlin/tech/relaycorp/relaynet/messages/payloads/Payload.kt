package tech.relaycorp.relaynet.messages.payloads

/**
 * RAMF payload in plaintext form.
 */
interface Payload {
    fun serializePlaintext(): ByteArray
}
