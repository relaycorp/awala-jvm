package tech.relaycorp.relaynet.keystores

class MockPublicKeyStore(
    private val savingException: Throwable? = null,
    private val fetchingException: Throwable? = null,
) : PublicKeyStore() {
    val keys: MutableMap<String, SessionPublicKeyData> = mutableMapOf()

    override fun saveKey(keyData: SessionPublicKeyData, peerPrivateAddress: String) {
        if (savingException != null) {
            throw savingException
        }
        this.keys[peerPrivateAddress] = keyData
    }

    override fun fetchKey(peerPrivateAddress: String): SessionPublicKeyData? {
        if (fetchingException != null) {
            throw fetchingException
        }

        return keys[peerPrivateAddress]
    }
}
