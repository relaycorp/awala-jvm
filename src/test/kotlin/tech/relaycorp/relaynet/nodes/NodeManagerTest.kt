package tech.relaycorp.relaynet.nodes

import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.ECDH_CURVE_MAP

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
            val manager = StubNodeManager(privateKeyStore)

            val (sessionKey, privateKey) = manager.generateSessionKey()

            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                "insert any address here"
            )
            assertNotNull(sessionKeyForDifferentPeer)
            assertEquals(
                privateKey.encoded.asList(),
                sessionKeyForDifferentPeer.encoded.asList()
            )
        }

        @Test
        fun `Key should be bound to a peer if explicitly set`() = runBlockingTest {
            val manager = StubNodeManager(privateKeyStore)

            val (sessionKey, privateKey) = manager.generateSessionKey(peerPrivateAddress)

            // We should get the key with the right peer
            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                peerPrivateAddress
            )
            assertNotNull(sessionKeyForDifferentPeer)
            assertEquals(
                privateKey.encoded.asList(),
                sessionKeyForDifferentPeer.encoded.asList()
            )
            // We shouldn't get the key with the wrong peer
            assertNull(
                privateKeyStore.retrieveSessionKey(
                    sessionKey.keyId,
                    "not $peerPrivateAddress"
                )
            )
        }

        @Test
        fun `Key should use P-256 by default`() = runBlockingTest {
            val manager = StubNodeManager(privateKeyStore)

            val (sessionKey) = manager.generateSessionKey(peerPrivateAddress)

            assertEquals(
                "P-256",
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }

        @ParameterizedTest(name = "Key should use {0} if explicitly requested")
        @EnumSource
        fun explicitCurveName(curve: ECDHCurve) = runBlockingTest {
            val manager = StubNodeManager(privateKeyStore, NodeCryptoOptions(curve))

            val (sessionKey) = manager.generateSessionKey(peerPrivateAddress)

            val curveName = ECDH_CURVE_MAP[curve]
            assertEquals(
                curveName,
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }
    }
}
