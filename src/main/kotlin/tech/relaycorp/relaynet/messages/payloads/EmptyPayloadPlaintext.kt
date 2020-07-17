package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.ramf.RAMFException

/**
 * Empty payload plaintext.
 */
class EmptyPayloadPlaintext : PayloadPlaintext {
    /**
     * Serialize empty payload plaintext.
     */
    override fun serialize() = ByteArray(0)

    companion object {
        /**
         * Deserialize empty payload plaintext.
         *
         * @throws RAMFException if `serialization` is not empty
         */
        @Throws(RAMFException::class)
        fun deserialize(serialization: ByteArray): EmptyPayloadPlaintext {
            if (serialization.isNotEmpty()) {
                throw RAMFException("Payload is not empty")
            }
            return EmptyPayloadPlaintext()
        }
    }
}
