package tech.relaycorp.relaynet.wrappers

import java.math.BigInteger
import java.security.SecureRandom

internal fun generateRandomBigInteger(): BigInteger {
    val random = SecureRandom()
    return BigInteger(64, random)
}

internal fun generateRandomOctets(size: Int): ByteArray {
    val random = SecureRandom()
    val bytes = ByteArray(size)
    random.nextBytes(bytes)
    return bytes
}
