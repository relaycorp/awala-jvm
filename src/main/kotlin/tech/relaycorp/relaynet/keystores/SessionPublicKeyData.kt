package tech.relaycorp.relaynet.keystores

import java.math.BigInteger
import java.time.ZonedDateTime

data class SessionPublicKeyData(
    val keyId: BigInteger,
    val keyDer: ByteArray,
    val creationTime: ZonedDateTime
)
