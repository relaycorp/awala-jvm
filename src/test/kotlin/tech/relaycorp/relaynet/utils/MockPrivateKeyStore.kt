package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.keystores.KeyStoreBackendException
import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

class MockPrivateKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : PrivateKeyStore() {
    val identityKeys: MutableMap<String, PrivateKeyData> = mutableMapOf()

    val sessionKeys: MutableMap<String, MutableMap<String, MutableMap<String, ByteArray>>> =
        mutableMapOf()

    fun clear() {
        identityKeys.clear()
        sessionKeys.clear()
    }

    override suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: PrivateKeyData
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving identity keys isn't supported", savingException)
        }
        setIdentityKey(privateAddress, keyData)
    }

    /**
     * Set an identity key, bypassing all the usual validation.
     */
    fun setIdentityKey(privateAddress: String, keyData: PrivateKeyData) {
        identityKeys[privateAddress] = keyData
    }

    override suspend fun retrieveIdentityKeyData(privateAddress: String): PrivateKeyData? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving identity keys isn't supported",
                savingException
            )
        }

        return identityKeys[privateAddress]
    }

    override suspend fun retrieveAllIdentityKeyData() = identityKeys.values.toList()

    override suspend fun saveSessionKeySerialized(
        keyId: String,
        keySerialized: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String?
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving session keys isn't supported", savingException)
        }
        setSessionKey(privateAddress, peerPrivateAddress, keyId, keySerialized)
    }

    /**
     * Set a session key, bypassing all the usual validation.
     */
    fun setSessionKey(
        privateAddress: String,
        peerPrivateAddress: String?,
        keyId: String,
        keySerialized: ByteArray
    ) {
        sessionKeys.putIfAbsent(privateAddress, mutableMapOf())
        val peerKey = peerPrivateAddress ?: "unbound"
        sessionKeys[privateAddress]!!.putIfAbsent(peerKey, mutableMapOf())
        sessionKeys[privateAddress]!![peerKey]!![keyId] = keySerialized
    }

    override suspend fun retrieveSessionKeySerialized(
        keyId: String,
        privateAddress: String,
        peerPrivateAddress: String,
    ): ByteArray? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving session keys isn't supported",
                retrievalException
            )
        }

        return sessionKeys[privateAddress]?.get(peerPrivateAddress)?.get(keyId)
            ?: sessionKeys[privateAddress]?.get("unbound")?.get(keyId)
    }

    override suspend fun deleteKeys(privateAddress: String) {
        identityKeys.remove(privateAddress)
        sessionKeys.remove(privateAddress)
    }

    override suspend fun deleteSessionKeysForPeer(peerPrivateAddress: String) {
        sessionKeys.values.forEach {
            it.remove(peerPrivateAddress)
        }
    }
}
