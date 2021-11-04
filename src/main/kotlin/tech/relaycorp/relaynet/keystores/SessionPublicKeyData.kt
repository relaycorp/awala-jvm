package tech.relaycorp.relaynet.keystores

/**
 * Key data as it should be represented by the underlying backend.
 */
data class SessionPublicKeyData(
    val keyId: ByteArray,
    val keyDer: ByteArray,
    val creationTimestamp: Long
)
