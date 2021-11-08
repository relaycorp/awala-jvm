package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

abstract class PrivateKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey, certificate: Certificate) {
        val keyData = IdentityPrivateKeyData(
            privateKey.encoded,
            certificate.serialize()
        )
        saveIdentityKeyData(certificate.subjectPrivateAddress, keyData)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveIdentityKeyData(
        privateAddress: String,
        keyData: IdentityPrivateKeyData
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(privateAddress: String): IdentityKeyPair {
        val keyData = retrieveIdentityKeyData(privateAddress)
            ?: throw MissingKeyException("There is no identity key for $privateAddress")

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
            Certificate.deserialize(certificateDer)
        )
    } catch (exc: KeyException) {
        throw KeyStoreBackendException("Private key is malformed", exc)
    } catch (exc: CertificateException) {
        throw KeyStoreBackendException("Certificate is malformed", exc)
    }
}
