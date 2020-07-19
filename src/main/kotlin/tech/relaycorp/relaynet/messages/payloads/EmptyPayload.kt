package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.ramf.RAMFException

/**
 * Empty payload plaintext.
 */
class EmptyPayload : UnencryptedPayload() {
    /**
     * Serialize empty payload plaintext.
     */
    override fun serializePlaintext() = ByteArray(0)

    companion object {
        /**
         * Deserialize empty payload plaintext.
         *
         * @throws RAMFException if `serialization` is not empty
         */
        @Throws(RAMFException::class)
        fun deserialize(serialization: ByteArray): EmptyPayload {
            if (serialization.isNotEmpty()) {
                throw RAMFException("Payload is not empty")
            }
            return EmptyPayload()
        }
    }
}
