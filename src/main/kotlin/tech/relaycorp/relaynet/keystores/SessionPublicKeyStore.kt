package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey

abstract class SessionPublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        key: SessionKey,
        nodeId: String,
        peerId: String,
        creationTime: ZonedDateTime = ZonedDateTime.now(),
    ) {
        val creationTimestamp = creationTime.toEpochSecond()

        val existingKeyData = retrieveKeyData(nodeId, peerId)
        if (existingKeyData != null && creationTimestamp < existingKeyData.creationTimestamp) {
            return
        }

        val keyData =
            SessionPublicKeyData(
                key.keyId,
                key.publicKey.encoded,
                creationTimestamp,
            )
        saveKeyData(keyData, nodeId, peerId)
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieve(
        nodeId: String,
        peerId: String,
    ): SessionKey {
        val keyData =
            retrieveKeyData(nodeId, peerId)
                ?: throw MissingKeyException("Node $nodeId has no session key for $peerId")

        val sessionPublicKey = keyData.keyDer.deserializeECPublicKey()
        return SessionKey(keyData.keyId, sessionPublicKey)
    }

    /**
     * Delete the session key for [peerId], if it exists under [nodeId].
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun delete(
        nodeId: String,
        peerId: String,
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        nodeId: String,
        peerId: String,
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveKeyData(
        nodeId: String,
        peerId: String,
    ): SessionPublicKeyData?
}
