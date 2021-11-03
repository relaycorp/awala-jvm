package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SymmetricCipher

data class NodeCryptoOptions(
    val ecdhCurve: ECDHCurve = ECDHCurve.P256,
    val symmetricCipher: SymmetricCipher = SymmetricCipher.AES_128,
    val hashingAlgorithm: HashingAlgorithm = HashingAlgorithm.SHA256,
)
