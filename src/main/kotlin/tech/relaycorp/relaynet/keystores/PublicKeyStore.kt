package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.SessionKey
import java.time.ZonedDateTime

abstract class PublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    fun saveSessionKey(
        key: SessionKey,
        peerPrivateAddress: String,
        creationTime: ZonedDateTime,
    ) {
        val existingKeyData = fetchKeyDataOrWrapException(peerPrivateAddress)
        if (existingKeyData != null && creationTime < existingKeyData.creationTime) {
            return
        }

        val keyData = SessionPublicKeyData(
            key.keyId,
            key.publicKey.encoded,
            creationTime
        )
        try {
            saveKey(keyData, peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to save session key", exc)
        }
    }

    protected abstract fun saveKey(keyData: SessionPublicKeyData, peerPrivateAddress: String)

    protected abstract fun fetchKey(peerPrivateAddress: String): SessionPublicKeyData?

    private fun fetchKeyDataOrWrapException(peerPrivateAddress: String): SessionPublicKeyData? {
        return try {
            fetchKey(peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to retrieve key", exc)
        }
    }
}
