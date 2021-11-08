package tech.relaycorp.relaynet.keystores

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

@ExperimentalCoroutinesApi
class PrivateKeyStoreTest {
    private val identityPrivateKey = KeyPairSet.PRIVATE_ENDPOINT.private
    private val identityCertificate = PDACertPath.PRIVATE_ENDPOINT

    private val sessionKeyGeneration = SessionKeyPair.generate()
    private val sessionKeyIdHex = Hex.toHexString(sessionKeyGeneration.sessionKey.keyId)

    private val ownPrivateAddress = identityCertificate.subjectPrivateAddress
    private val peerPrivateAddress = PDACertPath.PDA.subjectPrivateAddress

    @Nested
    inner class SaveIdentityKey {
        @Test
        fun `Key should be stored`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveIdentityKey(identityPrivateKey, identityCertificate)

            val privateAddress = identityCertificate.subjectPrivateAddress
            assertTrue(store.identityKeys.containsKey(privateAddress))
            val keyData = store.identityKeys[privateAddress]!!
            assertEquals(identityPrivateKey.encoded.asList(), keyData.privateKeyDer.asList())
            assertEquals(
                identityCertificate.serialize().asList(),
                keyData.certificateDer.asList()
            )
        }
    }

    @Nested
    inner class RetrieveIdentityKey {
        @Test
        fun `Existing key pair should be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveIdentityKey(identityPrivateKey, identityCertificate)

            val idKeyPair = store.retrieveIdentityKey(identityCertificate.subjectPrivateAddress)

            assertEquals(identityPrivateKey.encoded.asList(), idKeyPair.privateKey.encoded.asList())
            assertEquals(identityCertificate, idKeyPair.certificate)
        }

        @Test
        fun `Exception should be thrown if key pair does not exist`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            val exception = assertThrows<MissingKeyException> {
                store.retrieveIdentityKey(identityCertificate.subjectPrivateAddress)
            }

            assertEquals(
                "There is no identity key for ${identityCertificate.subjectPrivateAddress}",
                exception.message
            )
        }

        @Test
        fun `Malformed private keys should be refused`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            val privateAddress = identityCertificate.subjectPrivateAddress
            store.setIdentityKey(
                privateAddress,
                IdentityPrivateKeyData("malformed".toByteArray(), identityCertificate.serialize())
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Private key is malformed", exception.message)
            assertTrue(exception.cause is KeyException)
        }

        @Test
        fun `Malformed certificates should be refused`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            val privateAddress = identityCertificate.subjectPrivateAddress
            store.setIdentityKey(
                privateAddress,
                IdentityPrivateKeyData(identityPrivateKey.encoded, "malformed".toByteArray())
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveIdentityKey(privateAddress)
            }

            assertEquals("Certificate is malformed", exception.message)
            assertTrue(exception.cause is CertificateException)
        }
    }

    @Nested
    inner class RetrieveAllIdentityKeys {
        @Test
        fun `No key pair should be returned if there are none`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            assertEquals(0, store.retrieveAllIdentityKeys().size)
        }

        @Test
        fun `All stored key pairs should be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveIdentityKey(identityPrivateKey, identityCertificate)

            val allIdentityKeys = store.retrieveAllIdentityKeys()

            assertEquals(1, allIdentityKeys.size)
            assertEquals(
                IdentityKeyPair(identityPrivateKey, identityCertificate),
                allIdentityKeys.first()
            )
        }
    }

    @Nested
    inner class SaveSessionKey {
        @Test
        fun `Key should be stored`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
            )

            assertTrue(store.sessionKeys.containsKey(ownPrivateAddress))
            assertTrue(store.sessionKeys[ownPrivateAddress]!!.containsKey("unbound"))
        }

        @Test
        fun `Key should be unbound by default`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
            )

            val keySerialized =
                store.sessionKeys[ownPrivateAddress]!!["unbound"]!![sessionKeyIdHex]!!
            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                keySerialized.asList()
            )
        }

        @Test
        fun `Key should be bound to a peer if required`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
                peerPrivateAddress
            )

            val keySerialized =
                store.sessionKeys[ownPrivateAddress]!![peerPrivateAddress]!![sessionKeyIdHex]!!
            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                keySerialized.asList()
            )
        }
    }

    @Nested
    inner class RetrieveSessionKey {
        @Test
        fun `Unbound session keys should be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
            )

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
                "not $peerPrivateAddress"
            )

            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                sessionKey.encoded.asList()
            )
        }

        @Test
        fun `Bound session keys should be returned if peer matches`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
                peerPrivateAddress
            )

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
                peerPrivateAddress,
            )

            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                sessionKey.encoded.asList()
            )
        }

        @Test
        fun `Exception should be thrown if key pair does not exist`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            val exception = assertThrows<MissingKeyException> {
                store.retrieveSessionKey(
                    sessionKeyGeneration.sessionKey.keyId,
                    ownPrivateAddress,
                    peerPrivateAddress,
                )
            }

            assertEquals(
                "There is no session key for $peerPrivateAddress",
                exception.message
            )
        }

        @Test
        fun `Malformed private keys should be refused`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            val privateAddress = identityCertificate.subjectPrivateAddress
            store.setSessionKey(
                privateAddress,
                null,
                sessionKeyIdHex,
                "malformed".toByteArray()
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveSessionKey(
                    sessionKeyGeneration.sessionKey.keyId,
                    privateAddress,
                    peerPrivateAddress
                )
            }

            assertEquals("Session key $sessionKeyIdHex is malformed", exception.message)
            assertTrue(exception.cause is KeyException)
        }
    }
}
