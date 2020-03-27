package tech.relaycorp.relaynet

/**
 * Registries of cryptographic algorithms supported.
 *
 * Includes algorithms required and recommended by the Relaynet specs, and excludes those
 * explicitly banned (SHA-1 and MD5).
 *
 * See: https://specs.relaynet.link/RS-018
 */

enum class HashingAlgorithm {
    SHA256,
    SHA384,
    SHA512
}

enum class SymmetricEncryption {
    AES_GCM_128,
    AES_GCM_192,
    AES_GCM_256
}