package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey

abstract class SessionPublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        key: SessionKey,
        peerPrivateAddress: String,
        creationTime: ZonedDateTime = ZonedDateTime.now()
    ) {
        val creationTimestamp = creationTime.toEpochSecond()

        val existingKeyData = retrieveKeyData(peerPrivateAddress)
        if (existingKeyData != null && creationTimestamp < existingKeyData.creationTimestamp) {
            return
        }

        val keyData = SessionPublicKeyData(
            key.keyId,
            key.publicKey.encoded,
            creationTimestamp
        )
        saveKeyData(keyData, peerPrivateAddress)
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieve(peerPrivateAddress: String): SessionKey {
        val keyData = retrieveKeyData(peerPrivateAddress)
            ?: throw MissingKeyException("There is no session key for $peerPrivateAddress")

        val sessionPublicKey = keyData.keyDer.deserializeECPublicKey()
        return SessionKey(keyData.keyId, sessionPublicKey)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        peerPrivateAddress: String
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveKeyData(peerPrivateAddress: String):
        SessionPublicKeyData?
}
