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
 * Supported hashing algorithms
 */
public enum class HashingAlgorithm {
    SHA256,
    SHA384,
    SHA512
}

/**
 * Supported block ciphers
 */
public enum class SymmetricEncryption {
    AES_128,
    AES_192,
    AES_256
}
