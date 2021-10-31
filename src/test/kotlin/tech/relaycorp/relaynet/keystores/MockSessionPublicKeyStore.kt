package tech.relaycorp.relaynet.keystores

class MockSessionPublicKeyStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : SessionPublicKeyStore() {
    val keys: MutableMap<String, SessionPublicKeyData> = mutableMapOf()

    override fun saveKeyData(keyData: SessionPublicKeyData, peerPrivateAddress: String) {
        if (savingException != null) {
            throw savingException
        }
        this.keys[peerPrivateAddress] = keyData
    }

    override fun fetchKeyData(peerPrivateAddress: String): SessionPublicKeyData? {
        if (retrievalException != null) {
            throw retrievalException
        }

        return keys[peerPrivateAddress]
    }
}
