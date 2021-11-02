package tech.relaycorp.relaynet.keystores

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.PDACertPath
import tech.relaycorp.relaynet.SessionKey
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.util.encoders.Base64

@ExperimentalCoroutinesApi
class PrivateKeyStoreTest {
    private val identityPrivateKey = KeyPairSet.PRIVATE_GW.private
    private val identityCertificate = PDACertPath.PRIVATE_GW

    private val sessionKeyGeneration = SessionKey.generate()
    private val sessionKeyIdBase64 = Base64.toBase64String(sessionKeyGeneration.sessionKey.keyId)

    private val peerPrivateAddress = PDACertPath.PUBLIC_GW.subjectPrivateAddress

    @Nested
    inner class SaveIdentityKey {
        @Test
        fun `Key should be stored`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveIdentityKey(identityPrivateKey, identityCertificate)

            assertTrue(store.keys.containsKey("i-${identityCertificate.subjectPrivateAddress}"))
            val keyData = store.keys["i-${identityCertificate.subjectPrivateAddress}"]!!
            assertEquals(identityPrivateKey.encoded.asList(), keyData.privateKeyDer.asList())
            assertEquals(
                identityCertificate.serialize().asList(),
                keyData.certificateDer!!.asList()
            )
            assertNull(keyData.peerPrivateAddress)
        }

        @Test
        fun `Errors should be wrapped`() = runBlockingTest {
            val backendException = Exception("cannot save")
            val store = MockPrivateKeyStore(backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.saveIdentityKey(identityPrivateKey, identityCertificate)
            }

            assertEquals("Failed to save key", exception.message)
            assertEquals(backendException, exception.cause)
        }
    }

    @Nested
    inner class RetrieveIdentityKey {
        @Test
        fun `Existing key pair should be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveIdentityKey(identityPrivateKey, identityCertificate)

            val idKeyPair = store.retrieveIdentityKey(identityCertificate.subjectPrivateAddress)!!

            assertEquals(identityPrivateKey.encoded.asList(), idKeyPair.privateKey.encoded.asList())
            assertEquals(identityCertificate, idKeyPair.certificate)
        }

        @Test
        fun `Null should be returned if key pair does not exist`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            assertNull(store.retrieveIdentityKey(identityCertificate.subjectPrivateAddress))
        }

        @Test
        fun `Error should be thrown if certificate is missing`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            val privateAddress = identityCertificate.subjectPrivateAddress
            store.keys["i-$privateAddress"] = PrivateKeyData(
                identityPrivateKey.encoded
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveIdentityKey(privateAddress)
            }

            assertEquals(
                "Identity key pair $privateAddress is missing certificate",
                exception.message
            )
        }

        @Test
        fun `Errors should be wrapped`() = runBlockingTest {
            val backendException = Exception("oh noes")
            val store = MockPrivateKeyStore(retrievalException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveIdentityKey(identityCertificate.subjectPrivateAddress)
            }

            assertEquals("Failed to retrieve key", exception.message)
            assertEquals(backendException, exception.cause)
        }
    }

    @Nested
    inner class SaveSessionKey {
        @Test
        fun `Key should be stored`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId
            )

            assertTrue(store.keys.containsKey("s-$sessionKeyIdBase64"))
            val keyData = store.keys["s-$sessionKeyIdBase64"]!!
            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                keyData.privateKeyDer.asList()
            )
            assertNull(keyData.certificateDer)
        }

        @Test
        fun `Key should be unbound by default`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId
            )

            val keyData = store.keys["s-$sessionKeyIdBase64"]!!
            assertNull(keyData.peerPrivateAddress)
        }

        @Test
        fun `Key should be bound to a peer if required`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                peerPrivateAddress
            )

            val keyData = store.keys["s-$sessionKeyIdBase64"]!!
            assertEquals(peerPrivateAddress, keyData.peerPrivateAddress)
        }

        @Test
        fun `Errors should be wrapped`() = runBlockingTest {
            val backendException = Exception("oh noes")
            val store = MockPrivateKeyStore(backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    peerPrivateAddress
                )
            }

            assertEquals("Failed to save key", exception.message)
            assertEquals(backendException, exception.cause)
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
            )

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                "not $peerPrivateAddress"
            )

            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                sessionKey!!.encoded.asList()
            )
        }

        @Test
        fun `Bound session keys should be returned if peer matches`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                peerPrivateAddress
            )

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                peerPrivateAddress
            )

            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                sessionKey!!.encoded.asList()
            )
        }

        @Test
        fun `Keys bound to another peer should not be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                peerPrivateAddress
            )

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                "not $peerPrivateAddress"
            )

            assertNull(sessionKey)
        }

        @Test
        fun `Null should be returned if key pair does not exist`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            val sessionKey = store.retrieveSessionKey(
                sessionKeyGeneration.sessionKey.keyId,
                peerPrivateAddress
            )

            assertNull(sessionKey)
        }

        @Test
        fun `Errors should be wrapped`() = runBlockingTest {
            val backendException = Exception("oh noes")
            val store = MockPrivateKeyStore(retrievalException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveSessionKey(
                    sessionKeyGeneration.sessionKey.keyId,
                    peerPrivateAddress
                )
            }

            assertEquals("Failed to retrieve key", exception.message)
            assertEquals(backendException, exception.cause)
        }
    }
}