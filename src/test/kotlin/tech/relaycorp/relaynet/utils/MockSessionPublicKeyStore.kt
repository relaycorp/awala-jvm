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

    override suspend fun saveKeyData(
        keyData: SessionPublicKeyData,
        nodeId: String,
        peerId: String,
    ) {
        if (savingException != null) {
            throw savingException
        }
        this.keys["$nodeId,$peerId"] = keyData
    }

    override suspend fun retrieveKeyData(nodeId: String, peerId: String): SessionPublicKeyData? {
        if (retrievalException != null) {
            throw retrievalException
        }

        return keys["$nodeId,$peerId"]
    }

    override suspend fun delete(nodeId: String, peerId: String) {
        keys.remove("$nodeId,$peerId")
    }
}
