package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.nodeId

abstract class PrivateKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey) {
        val keyData = PrivateKeyData(privateKey.encoded)
        saveIdentityKeyData(privateKey.nodeId, keyData)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveIdentityKeyData(
        nodeId: String,
        keyData: PrivateKeyData
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(nodeId: String): PrivateKey {
        val keyData = retrieveIdentityKeyData(nodeId)
            ?: throw MissingKeyException("There is no identity key for $nodeId")

        return keyData.toIdentityPrivateKey()
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveIdentityKeyData(
        nodeId: String,
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
        nodeId: String,
        peerId: String? = null
    ) = saveSessionKeySerialized(
        formatSessionKeyId(keyId),
        privateKey.encoded,
        nodeId,
        peerId
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveSessionKeySerialized(
        keyId: String,
        keySerialized: ByteArray,
        nodeId: String,
        peerId: String?,
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveSessionKey(
        keyId: ByteArray,
        nodeId: String,
        peerId: String
    ): PrivateKey {
        val keyIdString = formatSessionKeyId(keyId)
        val privateKeySerialized = retrieveSessionKeySerialized(
            keyIdString,
            nodeId,
            peerId
        ) ?: throw MissingKeyException("There is no session key for $peerId")
        return try {
            privateKeySerialized.deserializeECKeyPair().private
        } catch (exc: KeyException) {
            throw KeyStoreBackendException("Session key $keyIdString is malformed", exc)
        }
    }

    /**
     * Delete the identity and session keys for the node identified by [nodeId].
     *
     * This is a no-op if the node doesn't exist.
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteKeys(nodeId: String)

    /**
     * Delete the session keys for the peer identified by [peerId].
     *
     * This is a no-op if the peer doesn't exist.
     */
    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteSessionKeysForPeer(peerId: String)

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveSessionKeySerialized(
        keyId: String,
        nodeId: String,
        peerId: String,
    ): ByteArray?

    private fun formatSessionKeyId(keyId: ByteArray) = Hex.toHexString(keyId)

    private fun PrivateKeyData.toIdentityPrivateKey() = try {
        privateKeyDer.deserializeRSAKeyPair().private
    } catch (exc: KeyException) {
        throw KeyStoreBackendException("Private key is malformed", exc)
    }
}
