package tech.relaycorp.relaynet.keystores

import java.time.ZoneId
import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore

class SessionPublicKeyStoreTest {
    private val nodeId = "0deadc0de"
    private val peerId = "0deadbeef"
    private val storeKey = "$nodeId,$peerId"
    private val creationTime: ZonedDateTime = ZonedDateTime.now(UTC).withNano(0)

    private val sessionKeyGeneration = SessionKeyPair.generate()
    private val sessionKey = sessionKeyGeneration.sessionKey

    @Nested
    inner class Save {
        @Test
        fun `Key data should be saved if there is no prior key for recipient`() = runTest {
            val store = MockSessionPublicKeyStore()

            store.save(sessionKey, nodeId, peerId)

            assertTrue(store.keys.containsKey(storeKey))
            val keyData = store.keys[storeKey]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
        }

        @Test
        fun `Key data should be saved if prior key is older`() = runTest {
            val store = MockSessionPublicKeyStore()
            val (oldSessionKey) = SessionKeyPair.generate()
            store.save(oldSessionKey, nodeId, peerId, creationTime.minusSeconds(1))

            store.save(sessionKey, nodeId, peerId, creationTime)

            val keyData = store.keys[storeKey]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
        }

        @Test
        fun `Key data should not be saved if prior key is newer`() = runTest {
            val store = MockSessionPublicKeyStore()
            store.save(sessionKey, nodeId, peerId, creationTime)

            val (oldSessionKey) = SessionKeyPair.generate()
            store.save(oldSessionKey, nodeId, peerId, creationTime.minusSeconds(1))

            val keyData = store.keys[storeKey]!!
            assertEquals(sessionKey.keyId.asList(), keyData.keyId.asList())
            assertEquals(sessionKey.publicKey.encoded.asList(), keyData.keyDer.asList())
            assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
        }

        @Nested
        inner class CreationTime {
            @Test
            fun `Now should be used by default`() = runTest {
                val now = ZonedDateTime.now(UTC)
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, nodeId, peerId)

                val keyData = store.keys[storeKey]!!
                val creationTimestamp = keyData.creationTimestamp
                assertTrue(now.toEpochSecond() <= creationTimestamp)
                assertTrue(creationTimestamp <= ZonedDateTime.now(UTC).toEpochSecond())
            }

            @Test
            fun `Any explicit time should be honored`() = runTest {
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, nodeId, peerId, creationTime)

                val keyData = store.keys[storeKey]!!
                assertEquals(creationTime.toEpochSecond(), keyData.creationTimestamp)
            }

            @Test
            fun `Time should be stored as UTC`() = runTest {
                val creationTime = ZonedDateTime.now(ZoneId.of("America/Caracas")).minusDays(1)
                val store = MockSessionPublicKeyStore()

                store.save(sessionKey, nodeId, peerId, creationTime)

                val keyData = store.keys[storeKey]!!
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
        fun `Key data should be returned if key for recipient exists`() = runTest {
            val store = MockSessionPublicKeyStore()
            store.save(sessionKey, nodeId, peerId, creationTime)

            val fetchedSessionKey = store.retrieve(nodeId, peerId)

            assertEquals(sessionKey, fetchedSessionKey)
        }

        @Test
        fun `Exception should be thrown if key for recipient does not exist`() = runTest {
            val store = MockSessionPublicKeyStore()

            val exception =
                assertThrows<MissingKeyException> { (store.retrieve(nodeId, peerId)) }

            assertEquals("Node $nodeId has no session key for $peerId", exception.message)
        }
    }
}
