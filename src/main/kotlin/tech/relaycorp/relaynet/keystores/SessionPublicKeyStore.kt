package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey

abstract class SessionPublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        key: SessionKey,
        peerId: String,
        creationTime: ZonedDateTime = ZonedDateTime.now()
    ) {
        val creationTimestamp = creationTime.toEpochSecond()

        val existingKeyData = retrieveKeyData(peerId)
        if (existingKeyData != null && creationTimestamp < existingKeyData.creationTimestamp) {
            return
        }

        val keyData = SessionPublicKeyData(
            key.keyId,
            key.publicKey.encoded,
            creationTimestamp
        )
        saveKeyData(keyData, peerId)
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieve(peerId: String): SessionKey {
        val keyData = retrieveKeyData(peerId)
            ?: throw MissingKeyException("There is no session key for $peerId")

        val sessionPublicKey = keyData.keyDer.deserializeECPublicKey()
        return SessionKey(keyData.keyId, sessionPublicKey)
    }

    /**
     * Delete the session key for [peerId], if it exists.
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun delete(peerId: String)

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        peerId: String
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveKeyData(peerId: String):
        SessionPublicKeyData?
}
