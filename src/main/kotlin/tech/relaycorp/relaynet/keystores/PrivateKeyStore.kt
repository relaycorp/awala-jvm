package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.math.BigInteger
import java.security.PrivateKey

abstract class PrivateKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey, certificate: Certificate) {
        val keyData = PrivateKeyData(privateKey.encoded, certificate.serialize())
        saveKeyDataOrWrapError(keyData, "i-${certificate.subjectPrivateAddress}")
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(privateAddress: String): IdentityKeyPair? {
        val keyData = retrieveKeyDataOrWrapError("i-$privateAddress") ?: return null

        if (keyData.certificateDer == null) {
            throw KeyStoreBackendException(
                "Identity key pair $privateAddress is missing certificate"
            )
        }

        return IdentityKeyPair(
            keyData.privateKeyDer.deserializeRSAKeyPair().private,
            Certificate.deserialize(keyData.certificateDer)
        )
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun saveSessionKey(
        privateKey: PrivateKey,
        keyId: BigInteger,
        peerPrivatAddress: String? = null
    ) {
        val keyData = PrivateKeyData(privateKey.encoded, peerPrivateAddress = peerPrivatAddress)
        saveKeyDataOrWrapError(keyData, "s-${keyId.toString(16)}")
    }

    protected abstract suspend fun saveKeyData(keyData: PrivateKeyData, keyId: String)

    protected abstract suspend fun retrieveKeyData(keyId: String): PrivateKeyData?

    @Throws(KeyStoreBackendException::class)
    private suspend fun saveKeyDataOrWrapError(keyData: PrivateKeyData, keyId: String) {
        try {
            saveKeyData(keyData, keyId)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to save key", exc)
        }
    }

    @Throws(KeyStoreBackendException::class)
    private suspend fun retrieveKeyDataOrWrapError(keyId: String): PrivateKeyData? {
        val keyData = try {
            retrieveKeyData(keyId)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to retrieve key", exc)
        }

        return keyData
    }
}
