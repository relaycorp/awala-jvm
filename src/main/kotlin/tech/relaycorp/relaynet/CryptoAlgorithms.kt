package tech.relaycorp.relaynet

/*
 * Registries of cryptographic algorithms supported.
 *
 * Includes algorithms required and recommended by the Relaynet specs, and excludes those
 * explicitly banned (SHA-1 and MD5).
 *
 * See: https://specs.relaynet.link/RS-018
 */

/**
 * Supported hashing algorithms.
 */
enum class HashingAlgorithm {
    SHA256,
    SHA384,
    SHA512
}

/**
 * Supported symmetric ciphers.
 */
enum class SymmetricCipher {
    AES_128,
    AES_192,
    AES_256
}

/**
 * Supported ECDH curves.
 */
enum class ECDHCurve {
    P256,
    P384,
    P521,
}
