package tech.relaycorp.relaynet.wrappers

import java.security.SecureRandom

fun generateRandom64BitValue(): Long {
    val random = SecureRandom()
    return random.nextLong()
}
