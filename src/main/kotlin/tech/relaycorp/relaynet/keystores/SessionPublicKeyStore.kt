package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey

abstract class SessionPublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun save(key: SessionKey, peerPrivateAddress: String, creationTime: ZonedDateTime) {
        val existingKeyData = retrieveKeyDataOrWrapException(peerPrivateAddress)
        if (existingKeyData != null && creationTime < existingKeyData.creationTime) {
            return
        }

        val keyData = SessionPublicKeyData(
            key.keyId,
            key.publicKey.encoded,
            creationTime
        )
        try {
            saveKeyData(keyData, peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to save session key", exc)
        }
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieve(peerPrivateAddress: String): SessionKey {
        val keyData = retrieveKeyDataOrWrapException(peerPrivateAddress)
            ?: throw MissingKeyException("There is no session key for $peerPrivateAddress")

        val sessionPublicKey = keyData.keyDer.deserializeECPublicKey()
        return SessionKey(keyData.keyId, sessionPublicKey)
    }

    protected abstract suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        peerPrivateAddress: String
    )

    protected abstract suspend fun retrieveKeyData(peerPrivateAddress: String):
        SessionPublicKeyData?

    private suspend fun retrieveKeyDataOrWrapException(
        peerPrivateAddress: String
    ): SessionPublicKeyData? {
        return try {
            retrieveKeyData(peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to retrieve key", exc)
        }
    }
}
