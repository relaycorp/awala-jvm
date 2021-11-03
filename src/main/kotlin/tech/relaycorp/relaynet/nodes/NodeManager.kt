package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload
import tech.relaycorp.relaynet.messages.payloads.Payload

abstract class NodeManager<P : Payload>(
    private val privateKeyStore: PrivateKeyStore,
    private val sessionPublicKeyStore: SessionPublicKeyStore,
    private val cryptoOptions: NodeCryptoOptions,
) {
    suspend fun generateSessionKeyPair(peerPrivateAddress: String? = null): SessionKeyPair {
        val keyGeneration = SessionKeyPair.generate(this.cryptoOptions.ecdhCurve)
        privateKeyStore.saveSessionKey(
            keyGeneration.privateKey,
            keyGeneration.sessionKey.keyId,
            peerPrivateAddress
        )
        return keyGeneration
    }

    /**
     * Encrypt and serialize the `payload`.
     *
     * Also store the new ephemeral session key.
     *
     * @param payload
     * @param peerPrivateAddress
     */
    @Throws(MissingSessionKeyException::class)
    suspend fun <P : EncryptedPayload> wrapMessagePayload(
        payload: P,
        peerPrivateAddress: String
    ): ByteArray {
        val recipientSessionKey = sessionPublicKeyStore.retrieve(peerPrivateAddress)
            ?: throw MissingSessionKeyException("There is no session key for $peerPrivateAddress")
        val senderSessionKeyPair = generateSessionKeyPair(peerPrivateAddress)
        return payload.encrypt(
            recipientSessionKey,
            senderSessionKeyPair,
            cryptoOptions.symmetricCipher,
            cryptoOptions.hashingAlgorithm,
        )
    }
}
