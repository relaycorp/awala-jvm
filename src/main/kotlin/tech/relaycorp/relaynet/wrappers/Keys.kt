package tech.relaycorp.relaynet.wrappers

import java.security.KeyPair
import java.security.KeyPairGenerator

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
