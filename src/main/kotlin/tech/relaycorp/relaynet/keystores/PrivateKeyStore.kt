package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.privateAddress

abstract class PrivateKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey) {
        val keyData = PrivateKeyData(privateKey.encoded)
        saveIdentityKeyData(privateKey.privateAddress, keyData)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: PrivateKeyData
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(privateAddress: String): PrivateKey {
        val keyData = retrieveIdentityKeyData(privateAddress)
            ?: throw MissingKeyException("There is no identity key for $privateAddress")

        return keyData.toIdentityPrivateKey()
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveIdentityKeyData(
        privateAddress: String,
    ): PrivateKeyData?

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAllIdentityKeys(): List<PrivateKey> =
        retrieveAllIdentityKeyData().map { it.toIdentityPrivateKey() }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveAllIdentityKeyData(): List<PrivateKeyData>

    @Throws(KeyStoreBackendException::class)
    suspend fun saveSessionKey(
        privateKey: PrivateKey,
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String? = null
    ) = saveSessionKeySerialized(
        formatSessionKeyId(keyId),
        privateKey.encoded,
        privateAddress,
        peerPrivateAddress
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveSessionKeySerialized(
        keyId: String,
        keySerialized: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String?,
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveSessionKey(
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String
    ): PrivateKey {
        val keyIdString = formatSessionKeyId(keyId)
        val privateKeySerialized = retrieveSessionKeySerialized(
            keyIdString,
            privateAddress,
            peerPrivateAddress
        ) ?: throw MissingKeyException("There is no session key for $peerPrivateAddress")
        return try {
            privateKeySerialized.deserializeECKeyPair().private
        } catch (exc: KeyException) {
            throw KeyStoreBackendException("Session key $keyIdString is malformed", exc)
        }
    }

    /**
     * Delete the identity and session keys for the node identified by [privateAddress].
     *
     * This is a no-op if the node doesn't exist.
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteKeys(privateAddress: String)

    /**
     * Delete the session keys for the peer identified by [peerPrivateAddress].
     *
     * This is a no-op if the peer doesn't exist.
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteSessionKeysForPeer(peerPrivateAddress: String)

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveSessionKeySerialized(
        keyId: String,
        privateAddress: String,
        peerPrivateAddress: String,
    ): ByteArray?

    private fun formatSessionKeyId(keyId: ByteArray) = Hex.toHexString(keyId)

    private fun PrivateKeyData.toIdentityPrivateKey() = try {
        privateKeyDer.deserializeRSAKeyPair().private
    } catch (exc: KeyException) {
        throw KeyStoreBackendException("Private key is malformed", exc)
    }
}
