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
        nodeId: String,
        keyData: PrivateKeyData,
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving identity keys isn't supported", savingException)
        }
        setIdentityKey(nodeId, keyData)
    }

    /**
     * Set an identity key, bypassing all the usual validation.
     */
    fun setIdentityKey(
        nodeId: String,
        keyData: PrivateKeyData,
    ) {
        identityKeys[nodeId] = keyData
    }

    override suspend fun retrieveIdentityKeyData(nodeId: String): PrivateKeyData? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving identity keys isn't supported",
                retrievalException,
            )
        }

        return identityKeys[nodeId]
    }

    override suspend fun retrieveAllIdentityKeyData() = identityKeys.values.toList()

    override suspend fun saveSessionKeySerialized(
        keyId: String,
        keySerialized: ByteArray,
        nodeId: String,
        peerId: String?,
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving session keys isn't supported", savingException)
        }
        setSessionKey(nodeId, peerId, keyId, keySerialized)
    }

    /**
     * Set a session key, bypassing all the usual validation.
     */
    fun setSessionKey(
        nodeId: String,
        peerId: String?,
        keyId: String,
        keySerialized: ByteArray,
    ) {
        sessionKeys.putIfAbsent(nodeId, mutableMapOf())
        val peerKey = peerId ?: "unbound"
        sessionKeys[nodeId]!!.putIfAbsent(peerKey, mutableMapOf())
        sessionKeys[nodeId]!![peerKey]!![keyId] = keySerialized
    }

    override suspend fun retrieveSessionKeySerialized(
        keyId: String,
        nodeId: String,
        peerId: String,
    ): ByteArray? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving session keys isn't supported",
                retrievalException,
            )
        }

        return sessionKeys[nodeId]?.get(peerId)?.get(keyId)
            ?: sessionKeys[nodeId]?.get("unbound")?.get(keyId)
    }

    override suspend fun deleteKeys(nodeId: String) {
        identityKeys.remove(nodeId)
        sessionKeys.remove(nodeId)
    }

    override suspend fun deleteSessionKeysForPeer(peerId: String) {
        sessionKeys.values.forEach {
            it.remove(peerId)
        }
    }
}
