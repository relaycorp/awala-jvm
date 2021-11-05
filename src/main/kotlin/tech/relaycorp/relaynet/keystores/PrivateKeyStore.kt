package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import org.bouncycastle.util.encoders.Hex
import tech.relaycorp.relaynet.wrappers.deserializeECKeyPair
import tech.relaycorp.relaynet.wrappers.deserializeRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class PrivateKeyStore {
    @Throws(KeyStoreBackendException::class)
    suspend fun saveIdentityKey(privateKey: PrivateKey, certificate: Certificate) {
        val keyData = PrivateKeyData(privateKey.encoded, certificate.serialize())
        val privateAddress = certificate.subjectPrivateAddress
        saveKeyData("i-$privateAddress", keyData, privateAddress)
    }

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveIdentityKey(privateAddress: String): IdentityKeyPair {
        val keyData = retrieveKeyData("i-$privateAddress", privateAddress)
            ?: throw MissingKeyException("There is no identity key for $privateAddress")

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
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String? = null
    ) {
        val keyData = PrivateKeyData(privateKey.encoded, peerPrivateAddress = peerPrivateAddress)
        saveKeyData(formatSessionKeyId(keyId), keyData, privateAddress)
    }

    @Throws(MissingKeyException::class, KeyStoreBackendException::class)
    suspend fun retrieveSessionKey(
        keyId: ByteArray,
        privateAddress: String,
        peerPrivateAddress: String
    ): PrivateKey {
        val keyData = retrieveKeyData(formatSessionKeyId(keyId), privateAddress)
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

    private fun formatSessionKeyId(keyId: ByteArray) = "s-${Hex.toHexString(keyId)}"

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun saveKeyData(
        keyId: String,
        keyData: PrivateKeyData,
        privateAddress: String
    )

    @Throws(KeyStoreBackendException::class)
    protected abstract suspend fun retrieveKeyData(
        keyId: String,
        privateAddress: String
    ): PrivateKeyData?
}
