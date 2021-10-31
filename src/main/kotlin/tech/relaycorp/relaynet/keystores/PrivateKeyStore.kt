package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey

abstract class PrivateKeyStore {
    suspend fun saveIdentityKey(privateKey: PrivateKey, certificate: Certificate) {
        val keyData = PrivateKeyData(privateKey.encoded, certificate.serialize())
        saveKeyDataOrWrapError(keyData, "i-${certificate.subjectPrivateAddress}")
    }

    protected abstract suspend fun saveKeyData(keyData: PrivateKeyData, keyId: String)

    private suspend fun saveKeyDataOrWrapError(keyData: PrivateKeyData, keyId: String) {
        try {
            saveKeyData(keyData, keyId)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to save key", exc)
        }
    }
}
