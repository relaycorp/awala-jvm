package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.messages.PARCEL_SERIALIZER
import tech.relaycorp.relaynet.messages.ParcelCollectionAck

/**
 * Message encapsulated in a cargo message set, classified with its type.
 */
class CargoMessage(val message: ByteArray) {
    var type: Type? = null
        private set

    init {
        if (10 <= message.size) {
            val formatSignature = message.slice(0..9)
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
}
