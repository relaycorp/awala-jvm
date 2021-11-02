package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.SessionKeyGeneration
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

abstract class NodeManager(
    private val privateKeyStore: PrivateKeyStore,
    private val cryptoOptions: NodeCryptoOptions?,
) {
    suspend fun generateSessionKey(peerPrivateAddress: String? = null): SessionKeyGeneration {
        val keyGeneration = SessionKey.generate(this.cryptoOptions?.ecdhCurve ?: ECDHCurve.P256)
        privateKeyStore.saveSessionKey(
            keyGeneration.privateKey,
            keyGeneration.sessionKey.keyId,
            peerPrivateAddress
        )
        return keyGeneration
    }
}
