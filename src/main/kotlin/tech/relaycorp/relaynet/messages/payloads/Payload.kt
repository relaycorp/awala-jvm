package tech.relaycorp.relaynet.messages.payloads

/**
 * RAMF payload in plaintext form.
 */
public interface Payload {
    public fun serializePlaintext(): ByteArray
}
