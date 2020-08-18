package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.ramf.RAMFException

/**
 * Empty payload plaintext.
 */
public class EmptyPayload : UnencryptedPayload() {
    /**
     * Serialize empty payload plaintext.
     */
    override fun serializePlaintext(): ByteArray = ByteArray(0)

    public companion object {
        /**
         * Deserialize empty payload plaintext.
         *
         * @throws RAMFException if `serialization` is not empty
         */
        @Throws(RAMFException::class)
        public fun deserialize(serialization: ByteArray): EmptyPayload {
            if (serialization.isNotEmpty()) {
                throw RAMFException("Payload is not empty")
            }
            return EmptyPayload()
        }
    }
}
