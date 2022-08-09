package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.keystores.SessionPublicKeyData
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

class MockSessionPublicKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : SessionPublicKeyStore() {
    val keys: MutableMap<String, SessionPublicKeyData> = mutableMapOf()

    fun clear() {
        keys.clear()
    }

    override suspend fun saveKeyData(keyData: SessionPublicKeyData, peerId: String) {
        if (savingException != null) {
            throw savingException
        }
        this.keys[peerId] = keyData
    }

    override suspend fun retrieveKeyData(peerId: String): SessionPublicKeyData? {
        if (retrievalException != null) {
            throw retrievalException
        }

        return keys[peerId]
    }

    override suspend fun delete(peerId: String) {
        keys.remove(peerId)
    }
}
