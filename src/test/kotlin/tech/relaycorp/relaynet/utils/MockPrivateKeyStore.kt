package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.keystores.PrivateKeyData
import tech.relaycorp.relaynet.keystores.PrivateKeyStore

class MockPrivateKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : PrivateKeyStore() {
    val keys: MutableMap<String, MutableMap<String, PrivateKeyData>> = mutableMapOf()

    fun clear() {
        keys.clear()
    }

    override suspend fun saveKeyData(
        keyId: String,
        keyData: PrivateKeyData,
        privateAddress: String,
    ) {
        if (savingException != null) {
            throw savingException
        }
        keys.putIfAbsent(privateAddress, mutableMapOf())
        keys[privateAddress]!![keyId] = keyData
    }

    override suspend fun retrieveKeyData(keyId: String, privateAddress: String): PrivateKeyData? {
        if (retrievalException != null) {
            throw retrievalException
        }

        return keys[privateAddress]?.get(keyId)
    }
}
