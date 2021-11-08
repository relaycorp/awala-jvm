package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.keystores.IdentityPrivateKeyData
import tech.relaycorp.relaynet.keystores.KeyStoreBackendException
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPrivateKeyData

class MockPrivateKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : PrivateKeyStore() {
    val identityKeys: MutableMap<String, IdentityPrivateKeyData> = mutableMapOf()

    val sessionKeys: MutableMap<String, MutableMap<String, SessionPrivateKeyData>> = mutableMapOf()

    fun clear() {
        identityKeys.clear()
        sessionKeys.clear()
    }

    override suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: IdentityPrivateKeyData
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving identity keys isn't supported", savingException)
        }
        identityKeys[privateAddress] = keyData
    }

    override suspend fun retrieveIdentityKeyData(privateAddress: String): IdentityPrivateKeyData? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving identity keys isn't supported",
                savingException
            )
        }

        return identityKeys[privateAddress]
    }

    override suspend fun retrieveAllIdentityKeyData() = identityKeys.values.toList()

    override suspend fun saveSessionKeyData(
        keyId: String,
        keyData: SessionPrivateKeyData,
        privateAddress: String
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving session keys isn't supported", savingException)
        }
        sessionKeys.putIfAbsent(privateAddress, mutableMapOf())
        sessionKeys[privateAddress]!![keyId] = keyData
    }

    override suspend fun retrieveSessionKeyData(
        keyId: String,
        privateAddress: String
    ): SessionPrivateKeyData? {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving session keys isn't supported",
                savingException
            )
        }

        return sessionKeys[privateAddress]?.get(keyId)
    }
}
