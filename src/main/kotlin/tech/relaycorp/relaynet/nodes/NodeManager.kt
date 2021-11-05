package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.keystores.KeyStoreBackendException
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload
import tech.relaycorp.relaynet.messages.payloads.Payload
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage
import tech.relaycorp.relaynet.ramf.InvalidPayloadException

abstract class NodeManager<P : Payload>(
    private val privateKeyStore: PrivateKeyStore,
    private val sessionPublicKeyStore: SessionPublicKeyStore,
    private val cryptoOptions: NodeCryptoOptions,
) {
    suspend fun generateSessionKeyPair(
        privateAddress: String,
        peerPrivateAddress: String? = null
    ): SessionKeyPair {
        val keyGeneration = SessionKeyPair.generate(this.cryptoOptions.ecdhCurve)
        privateKeyStore.saveSessionKey(
            keyGeneration.privateKey,
            keyGeneration.sessionKey.keyId,
            privateAddress,
            peerPrivateAddress,
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
     * @param privateAddress
     */
    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun <P : EncryptedPayload> wrapMessagePayload(
        payload: P,
        peerPrivateAddress: String,
        privateAddress: String,
    ): ByteArray {
        val recipientSessionKey = sessionPublicKeyStore.retrieve(peerPrivateAddress)
        val senderSessionKeyPair = generateSessionKeyPair(privateAddress, peerPrivateAddress)
        return payload.encrypt(
            recipientSessionKey,
            senderSessionKeyPair,
            cryptoOptions.symmetricCipher,
            cryptoOptions.hashingAlgorithm,
        )
    }

    /**
     * Decrypt and return the payload in the `message`.
     *
     * Also store the recipient's session key.
     *
     * @param message The RAMF message whose payload should be unwrapped.
     * @throws MissingKeyException if the payload was encrypted with an unknown key.
     * @throws KeyStoreBackendException if the private key couldn't be retrieved or the
     *     peer's session key could not be saved.
     * @throws InvalidPayloadException if the ciphertext or plaintext of the payload is invalid.
     */
    @Throws(
        MissingKeyException::class,
        KeyStoreBackendException::class,
        InvalidPayloadException::class,
    )
    suspend fun <P : EncryptedPayload> unwrapMessagePayload(message: EncryptedRAMFMessage<P>): P {
        val unwrapping = message.unwrapPayload(privateKeyStore)
        sessionPublicKeyStore.save(
            unwrapping.peerSessionKey,
            message.senderCertificate.subjectPrivateAddress,
            message.creationDate
        )
        return unwrapping.payload
    }
}
