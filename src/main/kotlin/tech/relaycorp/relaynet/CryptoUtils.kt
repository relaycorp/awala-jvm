@file:JvmName("CryptoUtils")

package tech.relaycorp.relaynet

import java.security.MessageDigest

internal fun getSHA256Digest(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}

internal fun getSHA256DigestHex(input: ByteArray) =
    getSHA256Digest(input).joinToString("") { "%02x".format(it) }
