package tech.relaycorp.relaynet.nodes

import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.bouncycastle.cms.KeyAgreeRecipientInformation
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.StubEncryptedPayload
import tech.relaycorp.relaynet.utils.StubEncryptedRAMFMessage
import tech.relaycorp.relaynet.wrappers.ECDH_CURVE_MAP
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.PAYLOAD_SYMMETRIC_CIPHER_OIDS
import tech.relaycorp.relaynet.wrappers.cms.SessionEnvelopedData

@OptIn(ExperimentalCoroutinesApi::class)
class NodeManagerTest {
    private val payload = StubEncryptedPayload("the payload")

    private val nodeId = PDACertPath.PRIVATE_ENDPOINT.subjectId

    private val peerId = PDACertPath.PDA.subjectId
    private val peerSessionKeyPair = SessionKeyPair.generate()
    private val peerSessionKey = peerSessionKeyPair.sessionKey
    private val peerSessionPrivateKey = peerSessionKeyPair.privateKey

    private val privateKeyStore = MockPrivateKeyStore()
    private val publicKeyStore = MockSessionPublicKeyStore()

    @BeforeEach
    @AfterAll
    fun clearStores() {
        privateKeyStore.clear()
        publicKeyStore.clear()
    }

    @Nested
    inner class GenerateSessionKeyPair {
        @Test
        fun `Key should not be bound to any peer by default`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val (sessionKey, privateKey) = manager.generateSessionKeyPair(nodeId)

            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                nodeId,
                "insert any address here"
            )
            assertNotNull(sessionKeyForDifferentPeer)
            assertEquals(
                privateKey.encoded.asList(),
                sessionKeyForDifferentPeer.encoded.asList()
            )
        }

        @Test
        fun `Key should be bound to a peer if explicitly set`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val (sessionKey, privateKey) = manager.generateSessionKeyPair(
                nodeId,
                peerId
            )

            // We should get the key with the right peer
            val sessionKeyForDifferentPeer = privateKeyStore.retrieveSessionKey(
                sessionKey.keyId,
                nodeId,
                peerId,
            )
            assertEquals(
                privateKey.encoded.asList(),
                sessionKeyForDifferentPeer.encoded.asList()
            )
            // We shouldn't get the key with the wrong peer
            assertThrows<MissingKeyException> {
                privateKeyStore.retrieveSessionKey(
                    sessionKey.keyId,
                    nodeId,
                    "not $peerId",
                )
            }
        }

        @Test
        fun `Key should use P-256 by default`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val (sessionKey) = manager.generateSessionKeyPair(peerId)

            assertEquals(
                "P-256",
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }

        @ParameterizedTest(name = "Key should use {0} if explicitly requested")
        @EnumSource
        fun explicitCurveName(curve: ECDHCurve) = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore, NodeCryptoOptions(curve))

            val (sessionKey) = manager.generateSessionKeyPair(peerId)

            val curveName = ECDH_CURVE_MAP[curve]
            assertEquals(
                curveName,
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }
    }

    @Nested
    inner class WrapMessagePayload {
        @BeforeEach
        fun registerPeerSessionKey() = runTest {
            publicKeyStore.save(peerSessionKey, nodeId, peerId)
        }

        @Test
        fun `There should be a session key for the recipient`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)
            publicKeyStore.clear()

            val exception = assertThrows<MissingKeyException> {
                manager.wrapMessagePayload(payload, peerId, nodeId)
            }

            assertEquals("Node $nodeId has no session key for $peerId", exception.message)
        }

        @Test
        fun `Payload should be encrypted with the recipient's key`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            assertTrue(envelopedData is SessionEnvelopedData)
            assertEquals(
                peerSessionKey.keyId.asList(),
                envelopedData.getRecipientKeyId().id.asList()
            )
            assertEquals(
                payload.serializePlaintext().asList(),
                envelopedData.decrypt(peerSessionPrivateKey).asList()
            )
        }

        @Test
        fun `The new ephemeral session key of the sender should be stored`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)
            assertEquals(0, privateKeyStore.sessionKeys.size)

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            assertTrue(envelopedData is SessionEnvelopedData)
            assertNotNull(
                privateKeyStore.retrieveSessionKey(
                    envelopedData.getOriginatorKey().keyId,
                    nodeId,
                    peerId,
                )
            )
        }

        @Test
        fun `The new ephemeral session key of the sender should be bound`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            assertTrue(envelopedData is SessionEnvelopedData)
            val keyId = envelopedData.getOriginatorKey().keyId
            assertThrows<MissingKeyException> {
                privateKeyStore.retrieveSessionKey(
                    keyId,
                    nodeId,
                    "not $peerId",
                )
            }
        }

        @Test
        fun `Cipher AES-128 should be used by default`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[SymmetricCipher.AES_128],
                envelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }

        @ParameterizedTest(name = "Cipher {0} should be used if explicitly requested")
        @EnumSource
        fun explicitCipher(cipher: SymmetricCipher) = runTest {
            val manager = StubNodeManager(
                privateKeyStore,
                publicKeyStore,
                NodeCryptoOptions(symmetricCipher = cipher)
            )

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[cipher],
                envelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }

        @Test
        fun `SHA-256 should be used in KDF by default`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                KeyAgreeRecipientInformation
            assertEquals(
                SessionEnvelopedData.ecdhAlgorithmByHashingAlgorithm[HashingAlgorithm.SHA256]!!.id,
                recipientInfo.keyEncryptionAlgOID
            )
        }

        @ParameterizedTest(
            name = "Hashing algorithm {0} should be used in KDF if explicitly requested"
        )
        @EnumSource
        fun explicitHashingAlgorithm(algorithm: HashingAlgorithm) = runTest {
            val manager = StubNodeManager(
                privateKeyStore,
                publicKeyStore,
                NodeCryptoOptions(hashingAlgorithm = algorithm)
            )

            val ciphertext =
                manager.wrapMessagePayload(payload, peerId, nodeId)

            val envelopedData = EnvelopedData.deserialize(ciphertext)
            val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                KeyAgreeRecipientInformation
            val ecdhAlgorithmOID =
                SessionEnvelopedData.ecdhAlgorithmByHashingAlgorithm[algorithm]!!
            assertEquals(
                ecdhAlgorithmOID.id,
                recipientInfo.keyEncryptionAlgOID
            )
        }
    }

    @Nested
    inner class UnwrapMessagePayload {
        private val ownSessionKeyPair = SessionKeyPair.generate()

        private val envelopedData = SessionEnvelopedData.encrypt(
            payload.serializePlaintext(),
            ownSessionKeyPair.sessionKey,
            peerSessionKeyPair,
        )
        private val message = StubEncryptedRAMFMessage(
            Recipient(PDACertPath.PRIVATE_ENDPOINT.subjectId),
            envelopedData.serialize(),
            PDACertPath.PDA
        )

        @BeforeEach
        fun registerOwnSessionKey() = runTest {
            privateKeyStore.saveSessionKey(
                ownSessionKeyPair.privateKey,
                ownSessionKeyPair.sessionKey.keyId,
                nodeId,
                peerId,
            )
        }

        @Test
        fun `Exception should be thrown if session key does not exist`() = runTest {
            privateKeyStore.clear()
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            assertThrows<MissingKeyException> {
                manager.unwrapMessagePayload(message)
            }
        }

        @Test
        fun `Payload should be returned decrypted`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)

            assertEquals(payload.payload, manager.unwrapMessagePayload(message).payload)
        }

        @Test
        fun `Peer session key should be stored`() = runTest {
            val manager = StubNodeManager(privateKeyStore, publicKeyStore)
            assertEquals(0, publicKeyStore.keys.size)

            manager.unwrapMessagePayload(message)

            assertEquals(peerSessionKey, publicKeyStore.retrieve(nodeId, peerId))
            val storedKey = publicKeyStore.keys["$nodeId,$peerId"]!!
            assertEquals(message.creationDate.toEpochSecond(), storedKey.creationTimestamp)
        }
    }
}
