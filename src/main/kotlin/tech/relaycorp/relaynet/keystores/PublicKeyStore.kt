package tech.relaycorp.relaynet.keystores

import org.bouncycastle.asn1.ASN1Integer
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey
import java.time.ZonedDateTime

abstract class PublicKeyStore {
    @Throws(KeyStoreBackendException::class)
    fun saveSessionKey(
        key: SessionKey,
        peerPrivateAddress: String,
        creationTime: ZonedDateTime,
    ) {
        val existingKeyData = fetchKeyDataOrWrapException(peerPrivateAddress)
        if (existingKeyData != null && creationTime < existingKeyData.creationTime) {
            return
        }

        val keyData = SessionPublicKeyData(
            ASN1Integer(key.keyId).encoded,
            key.publicKey.encoded,
            creationTime
        )
        try {
            saveKey(keyData, peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to save session key", exc)
        }
    }

    @Throws(KeyStoreBackendException::class)
    fun fetchSessionKey(peerPrivateAddress: String): SessionKey? {
        val keyData = fetchKeyDataOrWrapException(peerPrivateAddress) ?: return null

        val sessionKeyIdASN1 = ASN1Integer.getInstance(keyData.keyIdDer)
        val sessionPublicKey = keyData.keyDer.deserializeECPublicKey()
        return SessionKey(sessionKeyIdASN1.value, sessionPublicKey)
    }

    protected abstract fun saveKey(keyData: SessionPublicKeyData, peerPrivateAddress: String)

    protected abstract fun fetchKey(peerPrivateAddress: String): SessionPublicKeyData?

    private fun fetchKeyDataOrWrapException(peerPrivateAddress: String): SessionPublicKeyData? {
        return try {
            fetchKey(peerPrivateAddress)
        } catch (exc: Throwable) {
            throw KeyStoreBackendException("Failed to retrieve key", exc)
        }
    }
}
