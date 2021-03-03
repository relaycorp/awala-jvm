@file:JvmName("Keys")

package tech.relaycorp.relaynet.wrappers

import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.getSHA256DigestHex
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec

private const val DEFAULT_RSA_KEY_MODULUS = 2048
private const val MIN_RSA_KEY_MODULUS = 2048

private val ecdhCurveMap = mapOf(
    ECDHCurve.P256 to "P-256",
    ECDHCurve.P384 to "P-384",
    ECDHCurve.P521 to "P-521"
)

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
    val keyGen = KeyPairGenerator.getInstance("RSA", BC_PROVIDER)
    keyGen.initialize(modulus)
    return keyGen.generateKeyPair()
}

/**
 * Deserialize the RSA key pair from a private key serialization.
 */
fun ByteArray.deserializeRSAKeyPair(): KeyPair {
    val privateKeySpec = PKCS8EncodedKeySpec(this)
    val keyFactory = KeyFactory.getInstance("RSA", BC_PROVIDER)
    val privateKey = try {
        keyFactory.generatePrivate(privateKeySpec) as RSAPrivateCrtKey
    } catch (exc: InvalidKeySpecException) {
        throw KeyException("Value is not a valid RSA private key", exc)
    }
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
    val publicKey = keyFactory.generatePublic(publicKeySpec)
    return KeyPair(publicKey, privateKey)
}

fun ByteArray.deserializeRSAPublicKey() = deserializePublicKey("RSA")

fun ByteArray.deserializeECPublicKey() = deserializePublicKey("EC")

private fun ByteArray.deserializePublicKey(algorithm: String): PublicKey {
    val spec = X509EncodedKeySpec(this)
    val factory = KeyFactory.getInstance(algorithm, BC_PROVIDER)
    return try {
        factory.generatePublic(spec)
    } catch (exc: InvalidKeySpecException) {
        throw KeyException("Value is not a valid $algorithm public key", exc)
    }
}

/**
 * Generate an ECDH key pair.
 *
 * @param curve The curve
 */
fun generateECDHKeyPair(curve: ECDHCurve = ECDHCurve.P256): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("EC", BC_PROVIDER)
    val ecSpec = ECGenParameterSpec(ecdhCurveMap[curve])
    keyGen.initialize(ecSpec)
    return keyGen.generateKeyPair()
}

/**
 * Derive private address for Relaynet node from its public key.
 */
val PublicKey.privateAddress: String
    get() = "0${getSHA256DigestHex(this.encoded)}"
