package tech.relaycorp.relaynet.messages.payloads

/**
 * RAMF payload in plaintext form.
 */
interface PayloadPlaintext {
    fun serialize(): ByteArray
}
