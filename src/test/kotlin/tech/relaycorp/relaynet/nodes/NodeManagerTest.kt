package tech.relaycorp.relaynet.nodes

import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath

@OptIn(ExperimentalCoroutinesApi::class)
class NodeManagerTest {
    private val peerPrivateAddress = PDACertPath.PDA.subjectPrivateAddress

    private val privateKeyStore = MockPrivateKeyStore()
    private val publicKeyStore = MockSessionPublicKeyStore()

    @BeforeEach
    @AfterAll
    fun clearStores() {
        privateKeyStore.clear()
        publicKeyStore.clear()
    }

    @Nested
    inner class GenerateSessionKey {
        @Test
        fun `Key should not be bound to any peer by default`() = runBlockingTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val sessionKey = manager.generateSessionKey()

            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                "insert any address here"
            )
            assertNotNull(sessionKeyForDifferentPeer)
            assertEquals(
                sessionKey.publicKey.encoded.asList(),
                sessionKeyForDifferentPeer.encoded.asList()
            )
        }

        @Test
        @Disabled
        fun `Key should be bound to a peer if explicitly set`() = runBlockingTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val sessionKey = manager.generateSessionKey(peerPrivateAddress)

            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                "not $peerPrivateAddress"
            )
            assertNotNull(sessionKeyForDifferentPeer)
        }

        @Test
        @Disabled
        fun `Key should use P-256 by default`() {
        }

        @ParameterizedTest(name = "Key should use {0} if explicitly requested")
        @EnumSource
        @Disabled
        fun explicitCurveName(curve: ECDHCurve) {
        }
    }
}
