package tech.relaycorp.relaynet.keystores

class MockPrivateKeyStore(private val savingException: Throwable? = null) : PrivateKeyStore() {
    val keys: MutableMap<String, PrivateKeyData> = mutableMapOf()

    override suspend fun saveKeyData(keyData: PrivateKeyData, keyId: String) {
        if (savingException != null) {
            throw savingException
        }
        keys[keyId] = keyData
    }
}
