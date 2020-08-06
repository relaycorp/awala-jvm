package tech.relaycorp.relaynet.wrappers

import tech.relaycorp.relaynet.getSHA256DigestHex
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

private const val DEFAULT_RSA_KEY_MODULUS = 2048
private const val MIN_RSA_KEY_MODULUS = 2048

/**
 * Generate an RSA key pair.
 *
 * @param modulus The modulus
 * @throws KeyException If `modulus` is less than 2048
 */
@Throws(KeyException::class)
fun generateRSAKeyPair(modulus: Int = DEFAULT_RSA_KEY_MODULUS): KeyPair {
    if (modulus < MIN_RSA_KEY_MODULUS) {
        throw KeyException("Modulus should be at least $MIN_RSA_KEY_MODULUS (got $modulus)")
    }
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(modulus)
    return keyGen.generateKeyPair()
}

fun ByteArray.deserializeRSAPublicKey(): PublicKey {
    val spec = X509EncodedKeySpec(this)
    val factory = KeyFactory.getInstance("RSA")
    return try {
        factory.generatePublic(spec)
    } catch (exc: InvalidKeySpecException) {
        throw KeyException("Value is not a valid RSA public key", exc)
    }
}

/**
 * Derive private address for Relaynet node from its public key.
 */
val PublicKey.privateAddress: String
    get() = "0${getSHA256DigestHex(this.encoded)}"
