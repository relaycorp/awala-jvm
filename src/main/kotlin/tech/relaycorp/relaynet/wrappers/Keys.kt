package tech.relaycorp.relaynet.wrappers

import java.security.KeyPair
import java.security.KeyPairGenerator

@Throws(KeyException::class)
fun generateRSAKeyPair(modulus: Int): KeyPair {
    if (modulus < 2048) {
        throw KeyException("The modulus should be at least 2048 (got $modulus)")
    }
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(modulus) // `modulus` should be >= 2048 and default to 2048
    return keyGen.generateKeyPair()
}
