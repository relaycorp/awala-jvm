package tech.relaycorp.relaynet.ramf

fun skipFormatSignature(ramfMessage: ByteArray): ByteArray {
    return ramfMessage.copyOfRange(7, ramfMessage.lastIndex + 1)
}
