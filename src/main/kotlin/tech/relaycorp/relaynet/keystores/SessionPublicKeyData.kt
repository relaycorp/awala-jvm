package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime

/**
 * Key data as it should be represented by the underlying backend.
 */
data class SessionPublicKeyData(
    val keyId: ByteArray,
    val keyDer: ByteArray,
    val creationTime: ZonedDateTime
)
