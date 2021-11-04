package tech.relaycorp.relaynet.keystores

import java.time.ZoneId
import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import kotlin.test.assertEquals
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
    private val creationTime: ZonedDateTime = ZonedDateTime.now(UTC).withNano(0)

    private val sessionKeyGeneration = SessionKeyPair.generate()
    private val sessionKey = sessionKeyGeneration.sessionKey

    @Nested
    inner class Save {
        @Test
        fun `Key data should be saved if there is no prior key for recipient`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()

            store.save(sessionKey, peerPrivateAddress)

            assertTrue(store.keys.containsKey(peerPrivateAddress))
            val keyData = store.keys[peerPrivateAddress]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
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
            assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
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
            assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
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

        @Nested
        inner class CreationTime {
            @Test
            fun `Now should be used by default`() = runBlockingTest {
                val now = ZonedDateTime.now(UTC)
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, peerPrivateAddress)

                val keyData = store.keys[peerPrivateAddress]!!
                val creationTimestamp = keyData.creationTimestamp
                assertTrue(now.toEpochSecond() <= creationTimestamp)
                assertTrue(creationTimestamp <= ZonedDateTime.now(UTC).toEpochSecond())
            }

            @Test
            fun `Any explicit time should be honored`() = runBlockingTest {
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, peerPrivateAddress, creationTime)

                val keyData = store.keys[peerPrivateAddress]!!
                assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
            }

            @Test
            fun `Time should be stored as UTC`() = runBlockingTest {
                val creationTime = ZonedDateTime.now(ZoneId.of("America/Caracas")).minusDays(1)
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, peerPrivateAddress, creationTime)

                val keyData = store.keys[peerPrivateAddress]!!
                assertEquals(
                    creationTime.withZoneSameInstant(UTC).toEpochSecond(),
                    keyData.creationTimestamp
                )
            }
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
        fun `Exception should be thrown if key for recipient does not exist`() = runBlockingTest {
            val store = MockSessionPublicKeyStore()

            val exception =
                assertThrows<MissingKeyException> { (store.retrieve(peerPrivateAddress)) }

            assertEquals("There is no session key for $peerPrivateAddress", exception.message)
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
