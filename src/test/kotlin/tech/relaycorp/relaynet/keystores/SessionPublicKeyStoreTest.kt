package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore

@OptIn(ExperimentalCoroutinesApi::class)
class SessionPublicKeyStoreTest {
    private val peerPrivateAddress = "0deadbeef"
    private val creationTime: ZonedDateTime = ZonedDateTime.now()

    private val sessionKeyGeneration = SessionKeyPair.generate()
    private val sessionKey = sessionKeyGeneration.sessionKey

    @Nested
    inner class Save {
        @Test
        fun `Key data should be saved if there is no prior key for recipient`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()

            store.save(sessionKey, peerPrivateAddress, creationTime)

            assertTrue(store.keys.containsKey(peerPrivateAddress))
            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Key data should be saved if prior key is older`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()
            val (oldSessionKey) = SessionKeyPair.generate()
            store.save(oldSessionKey, peerPrivateAddress, creationTime.minusSeconds(1))

            store.save(sessionKey, peerPrivateAddress, creationTime)

            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Key data should not be saved if prior key is newer`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()
            store.save(sessionKey, peerPrivateAddress, creationTime)

            val (oldSessionKey) = SessionKeyPair.generate()
            store.save(oldSessionKey, peerPrivateAddress, creationTime.minusSeconds(1))

            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Any error while retrieving existing key should be wrapped`() = runBlockingTest {
            val backendException = Exception("Something went wrong")
            val store = MockSessionPublicKeyStore(retrievalException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.save(sessionKey, peerPrivateAddress, creationTime)
            }

            assertEquals(exception.message, "Failed to retrieve key")
            assertEquals(exception.cause, backendException)
        }

        @Test
        fun `Any error while saving existing key should be wrapped`() = runBlockingTest {
            val backendException = Exception("Something went wrong")
            val store = MockSessionPublicKeyStore(backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.save(sessionKey, peerPrivateAddress, creationTime)
            }

            assertEquals(exception.message, "Failed to save session key")
            assertEquals(exception.cause, backendException)
        }
    }

    @Nested
    inner class Retrieve {
        @Test
        fun `Key data should be returned if key for recipient exists`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()
            store.save(sessionKey, peerPrivateAddress, creationTime)

            val fetchedSessionKey = store.retrieve(peerPrivateAddress)

            assertEquals(sessionKey, fetchedSessionKey)
        }

        @Test
        fun `Null should be returned if key for recipient does not exist`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()

            assertNull(store.retrieve(peerPrivateAddress))
        }

        @Test
        fun `Retrieval errors should be wrapped`() = runBlockingTest {
            val backendException = Exception("whoops")
            val store = MockSessionPublicKeyStore(retrievalException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieve(peerPrivateAddress)
            }

            assertEquals(exception.message, "Failed to retrieve key")
            assertEquals(exception.cause, backendException)
        }
    }
}
