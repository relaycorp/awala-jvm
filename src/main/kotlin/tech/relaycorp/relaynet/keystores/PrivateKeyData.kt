package tech.relaycorp.relaynet.keystores

data class PrivateKeyData(
    val privateKeyDer: ByteArray,
    val certificateDer: ByteArray? = null,
    val peerPrivateAddress: String? = null
)
