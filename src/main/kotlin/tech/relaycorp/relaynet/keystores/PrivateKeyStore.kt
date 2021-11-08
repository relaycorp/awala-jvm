package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate

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

        return IdentityKeyPair(
            keyData.privateKeyDer.deserializeRSAKeyPair().private,
            Certificate.deserialize(keyData.certificateDer)
        )
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveIdentityKeyData(
        privateAddress: String,
    ): IdentityPrivateKeyData?

    @Throws(KeyStoreBackendException::class)
    suspend fun saveSessionKey(
        privateKey: PrivateKey,
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String? = null
    ) {
        val keyData = SessionPrivateKeyData(privateKey.encoded, peerPrivateAddress)
        saveSessionKeyData(formatSessionKeyId(keyId), keyData, privateAddress)
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveSessionKeyData(
        keyId: String,
        keyData: SessionPrivateKeyData,
        privateAddress: String,
    )

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveSessionKey(
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String
    ): PrivateKey {
        val keyData = retrieveSessionKeyData(formatSessionKeyId(keyId), privateAddress)
            ?: throw MissingKeyException("There is no session key for $peerPrivateAddress")
        if (
            keyData.peerPrivateAddress != null && keyData.peerPrivateAddress != peerPrivateAddress
        ) {
            throw MissingKeyException(
                "Session key is bound to ${keyData.peerPrivateAddress} (not $peerPrivateAddress)"
            )
        }
        return keyData.privateKeyDer.deserializeECKeyPair().private
    }

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveSessionKeyData(
        keyId: String,
        privateAddress: String
    ): SessionPrivateKeyData?

    private fun formatSessionKeyId(keyId: ByteArray) = Hex.toHexString(keyId)
}
