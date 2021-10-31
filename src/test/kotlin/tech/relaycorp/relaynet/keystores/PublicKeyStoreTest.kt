package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.SessionKey
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PublicKeyStoreTest {
    private val peerPrivateAddress = "0deadbeef"
    private val creationTime: ZonedDateTime = ZonedDateTime.now()

    private val sessionKeyGeneration = SessionKey.generate()
    private val sessionKey = sessionKeyGeneration.sessionKey

    @Nested
    inner class SaveSessionKey {
        @Test
        fun `Key data should be saved if there is no prior key for recipient`() {
            val store = MockPublicKeyStore()

            store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)

            assertTrue(store.keys.containsKey(peerPrivateAddress))
            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId, keyData.keyId)
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Key data should be saved if prior key is older`() {
            val store = MockPublicKeyStore()
            val (oldSessionKey) = SessionKey.generate()
            store.saveSessionKey(oldSessionKey, peerPrivateAddress, creationTime.minusSeconds(1))

            store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)

            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId, keyData.keyId)
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Key data should not be saved if prior key is newer`() {
            val store = MockPublicKeyStore()
            store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)

            val (oldSessionKey) = SessionKey.generate()
            store.saveSessionKey(oldSessionKey, peerPrivateAddress, creationTime.minusSeconds(1))

            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId, keyData.keyId)
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime, keyData.creationTime)
        }

        @Test
        fun `Any error while retrieving existing key should be wrapped`() {
            val backendException = Exception("Something went wrong")
            val store = MockPublicKeyStore(fetchingException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)
            }

            assertEquals(exception.message, "Failed to retrieve key")
            assertEquals(exception.cause, backendException)
        }

        @Test
        fun `Any error while saving existing key should be wrapped`() {
            val backendException = Exception("Something went wrong")
            val store = MockPublicKeyStore(backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)
            }

            assertEquals(exception.message, "Failed to save session key")
            assertEquals(exception.cause, backendException)
        }
    }

    @Nested
    inner class FetchSessionKey {
        @Test
        fun `Key data should be returned if key for recipient exists`() {
            val store = MockPublicKeyStore()
            store.saveSessionKey(sessionKey, peerPrivateAddress, creationTime)

            val fetchedSessionKey = store.fetchSessionKey(peerPrivateAddress)

            assertEquals(fetchedSessionKey!!.keyId, sessionKey.keyId)
            assertEquals(
                fetchedSessionKey.publicKey.encoded.asList(),
                sessionKey.publicKey.encoded.asList()
            )
        }

        @Test
        fun `Null should be returned if key for recipient does not exist`() {
            val store = MockPublicKeyStore()

            assertNull(store.fetchSessionKey(peerPrivateAddress))
        }

        @Test
        fun `Retrieval errors should be wrapped`() {
            val backendException = Exception("whoops")
            val store = MockPublicKeyStore(fetchingException = backendException)

            val exception = assertThrows<KeyStoreBackendException> {
                store.fetchSessionKey(peerPrivateAddress)
            }

            assertEquals(exception.message, "Failed to retrieve key")
            assertEquals(exception.cause, backendException)
        }
    }
}
