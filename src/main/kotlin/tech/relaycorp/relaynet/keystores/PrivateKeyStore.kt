package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

abstract class PrivateKeyStore {
    @Throws(IllegalArgumentException::class, KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey, certificates: List<Certificate>) {
        val firstCertificate = certificates.firstOrNull()
            ?: throw IllegalArgumentException("Certificate list cannot be empty")

        val keyData = IdentityPrivateKeyData(
            privateKey.encoded,
            certificates.map { it.serialize() }
        )
        saveIdentityKeyData(firstCertificate.subjectPrivateAddress, keyData)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: IdentityPrivateKeyData
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(privateAddress: String): IdentityKeyPair {
        val keyData = retrieveIdentityKeyData(privateAddress)
        if (keyData == null || keyData.certificatesDer.isEmpty()) {
            throw MissingKeyException("There is no identity key for $privateAddress")
        }
        return keyData.toIdentityPrivateKey()
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveIdentityKeyData(
        privateAddress: String,
    ): IdentityPrivateKeyData?

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAllIdentityKeys(): List<IdentityKeyPair> =
        retrieveAllIdentityKeyData().map { it.toIdentityPrivateKey() }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveAllIdentityKeyData(): List<IdentityPrivateKeyData>

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

    private fun IdentityPrivateKeyData.toIdentityPrivateKey() = try {
        IdentityKeyPair(
            privateKeyDer.deserializeRSAKeyPair().private,
            certificatesDer.map { Certificate.deserialize(it) }
        )
    } catch (exc: KeyException) {
        throw KeyStoreBackendException("Private key is malformed", exc)
    } catch (exc: CertificateException) {
        throw KeyStoreBackendException("Certificate is malformed", exc)
    }
}
