package tech.relaycorp.relaynet.keystores

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.nodeId

@ExperimentalCoroutinesApi
class PrivateKeyStoreTest {
    private val identityPrivateKey = KeyPairSet.PRIVATE_ENDPOINT.private

    private val sessionKeyGeneration = SessionKeyPair.generate()
    private val sessionKeyIdHex = Hex.toHexString(sessionKeyGeneration.sessionKey.keyId)

    private val nodeId = KeyPairSet.PRIVATE_ENDPOINT.public.nodeId
    private val peerId = KeyPairSet.PDA_GRANTEE.public.nodeId

    @Nested
    inner class SaveIdentityKey {
        @Test
        fun `Key should be stored`() =
            runTest {
                val store = MockPrivateKeyStore()

                store.saveIdentityKey(identityPrivateKey)

                val nodeId = identityPrivateKey.nodeId
                assertTrue(store.identityKeys.containsKey(nodeId))
                val keyData = store.identityKeys[nodeId]!!
                assertEquals(identityPrivateKey.encoded.asList(), keyData.privateKeyDer.asList())
            }
    }

    @Nested
    inner class RetrieveIdentityKey {
        @Test
        fun `Existing key pair should be returned`() =
            runTest {
                val store = MockPrivateKeyStore()
                store.saveIdentityKey(identityPrivateKey)

                val idPrivateKey = store.retrieveIdentityKey(identityPrivateKey.nodeId)

                assertEquals(identityPrivateKey.encoded.asList(), idPrivateKey.encoded.asList())
            }

        @Test
        fun `Exception should be thrown if key pair does not exist`() =
            runTest {
                val store = MockPrivateKeyStore()

                val exception =
                    assertThrows<MissingKeyException> {
                        store.retrieveIdentityKey(identityPrivateKey.nodeId)
                    }

                assertEquals(
                    "There is no identity key for ${identityPrivateKey.nodeId}",
                    exception.message,
                )
            }

        @Test
        fun `Malformed private keys should be refused`() =
            runTest {
                val store = MockPrivateKeyStore()
                val nodeId = identityPrivateKey.nodeId
                store.setIdentityKey(
                    nodeId,
                    PrivateKeyData("malformed".toByteArray()),
                )

                val exception =
                    assertThrows<KeyStoreBackendException> {
                        store.retrieveIdentityKey(nodeId)
                    }

                assertEquals("Private key is malformed", exception.message)
                assertTrue(exception.cause is KeyException)
            }
    }

    @Nested
    inner class RetrieveAllIdentityKeys {
        @Test
        fun `No key pair should be returned if there are none`() =
            runTest {
                val store = MockPrivateKeyStore()

                assertEquals(0, store.retrieveAllIdentityKeys().size)
            }

        @Test
        fun `All stored key pairs should be returned`() =
            runTest {
                val store = MockPrivateKeyStore()
                store.saveIdentityKey(identityPrivateKey)

                val allIdentityKeys = store.retrieveAllIdentityKeys()

                assertEquals(1, allIdentityKeys.size)
                assertEquals(
                    identityPrivateKey,
                    allIdentityKeys.first(),
                )
            }
    }

    @Nested
    inner class SaveSessionKey {
        @Test
        fun `Key should be stored`() =
            runTest {
                val store = MockPrivateKeyStore()

                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    nodeId,
                )

                assertTrue(store.sessionKeys.containsKey(nodeId))
                assertTrue(store.sessionKeys[nodeId]!!.containsKey("unbound"))
            }

        @Test
        fun `Key should be unbound by default`() =
            runTest {
                val store = MockPrivateKeyStore()

                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    nodeId,
                )

                val keySerialized =
                    store.sessionKeys[nodeId]!!["unbound"]!![sessionKeyIdHex]!!
                assertEquals(
                    sessionKeyGeneration.privateKey.encoded.asList(),
                    keySerialized.asList(),
                )
            }

        @Test
        fun `Key should be bound to a peer if required`() =
            runTest {
                val store = MockPrivateKeyStore()

                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    nodeId,
                    peerId,
                )

                val keySerialized =
                    store.sessionKeys[nodeId]!![peerId]!![sessionKeyIdHex]!!
                assertEquals(
                    sessionKeyGeneration.privateKey.encoded.asList(),
                    keySerialized.asList(),
                )
            }
    }

    @Nested
    inner class RetrieveSessionKey {
        @Test
        fun `Unbound session keys should be returned`() =
            runTest {
                val store = MockPrivateKeyStore()
                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    nodeId,
                )

                val sessionKey =
                    store.retrieveSessionKey(
                        sessionKeyGeneration.sessionKey.keyId,
                        nodeId,
                        "not $peerId",
                    )

                assertEquals(
                    sessionKeyGeneration.privateKey.encoded.asList(),
                    sessionKey.encoded.asList(),
                )
            }

        @Test
        fun `Bound session keys should be returned if peer matches`() =
            runTest {
                val store = MockPrivateKeyStore()
                store.saveSessionKey(
                    sessionKeyGeneration.privateKey,
                    sessionKeyGeneration.sessionKey.keyId,
                    nodeId,
                    peerId,
                )

                val sessionKey =
                    store.retrieveSessionKey(
                        sessionKeyGeneration.sessionKey.keyId,
                        nodeId,
                        peerId,
                    )

                assertEquals(
                    sessionKeyGeneration.privateKey.encoded.asList(),
                    sessionKey.encoded.asList(),
                )
            }

        @Test
        fun `Exception should be thrown if key pair does not exist`() =
            runTest {
                val store = MockPrivateKeyStore()

                val exception =
                    assertThrows<MissingKeyException> {
                        store.retrieveSessionKey(
                            sessionKeyGeneration.sessionKey.keyId,
                            nodeId,
                            peerId,
                        )
                    }

                assertEquals(
                    "There is no session key for $peerId",
                    exception.message,
                )
            }

        @Test
        fun `Malformed private keys should be refused`() =
            runTest {
                val store = MockPrivateKeyStore()
                store.setSessionKey(
                    nodeId,
                    null,
                    sessionKeyIdHex,
                    "malformed".toByteArray(),
                )

                val exception =
                    assertThrows<KeyStoreBackendException> {
                        store.retrieveSessionKey(
                            sessionKeyGeneration.sessionKey.keyId,
                            nodeId,
                            peerId,
                        )
                    }

                assertEquals("Session key $sessionKeyIdHex is malformed", exception.message)
                assertTrue(exception.cause is KeyException)
            }
    }
}
