package tech.relaycorp.relaynet.messages.payloads

class CargoMessage(val message: ByteArray) {
    companion object {
        enum class Type(protected val concreteMessageType: Byte) {
            PARCEL(0x50),
            PCA(0x51)
        }
    }
}
