package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.messages.PARCEL_SERIALIZER
import tech.relaycorp.relaynet.messages.ParcelCollectionAck
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage

/**
 * Message encapsulated in a cargo message set, classified with its type.
 */
class CargoMessage(val messageSerialized: ByteArray) {
    var type: Type? = null
        private set

    init {
        if (10 <= messageSerialized.size) {
            val formatSignature = messageSerialized.slice(0..9)
            for (typeEnum in Type.values()) {
                if (typeEnum.formatSignature == formatSignature) {
                    type = typeEnum
                    break
                }
            }
        }
    }

    enum class Type(internal val formatSignature: List<Byte>) {
        PARCEL(PARCEL_SERIALIZER.formatSignature.asList()),
        PCA(ParcelCollectionAck.FORMAT_SIGNATURE.asList())
    }

    companion object {
        /**
         * Number of octets needed to represent the type and length of an 8 MiB value in DER.
         */
        internal const val DER_TL_OVERHEAD_OCTETS = 5

        /**
         * Maximum number of octets for any serialized message to be encapsulated in a cargo.
         *
         * This is the result of subtracting the TLVs for the SET and OCTET STRING values from
         * the maximum size of an SDU to be encrypted.
         */
        internal const val MAX_LENGTH =
            EncryptedRAMFMessage.MAX_PAYLOAD_PLAINTEXT_LENGTH - (DER_TL_OVERHEAD_OCTETS * 2)
    }
}
