package tech.relaycorp.relaynet

/**
 * Supported hashing algorithms.
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
