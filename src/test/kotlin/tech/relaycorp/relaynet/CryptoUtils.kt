package tech.relaycorp.relaynet

import java.security.MessageDigest

fun sha256(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}
