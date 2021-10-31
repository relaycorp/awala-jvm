package tech.relaycorp.relaynet.keystores

class MockPrivateKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : PrivateKeyStore() {
    val keys: MutableMap<String, PrivateKeyData> = mutableMapOf()

    override suspend fun saveKeyData(keyData: PrivateKeyData, keyId: String) {
        if (savingException != null) {
            throw savingException
        }
        keys[keyId] = keyData
    }

    override suspend fun retrieveKeyData(keyId: String): PrivateKeyData? {
        if (retrievalException != null) {
            throw retrievalException
        }

        return keys[keyId]
    }
}
