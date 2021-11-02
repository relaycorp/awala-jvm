package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.SessionKeyGeneration
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.messages.payloads.Payload

abstract class NodeManager<P : Payload>(
    private val privateKeyStore: PrivateKeyStore,
    private val sessionPublicKeyStore: SessionPublicKeyStore,
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

    suspend fun wrapMessagePayload(payload: P, peerPrivateAddress: String): ByteArray {
        TODO()
    }
}
