package tech.relaycorp.relaynet.wrappers

import java.math.BigInteger
import java.security.SecureRandom

fun generateRandomBigInteger(): BigInteger {
    val random = SecureRandom()
    return BigInteger(64, random)
}
