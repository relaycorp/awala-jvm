package tech.relaycorp.relaynet.keystores

import kotlin.test.assertEquals
import kotlin.test.assertNull
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
            assertTrue(store.sessionKeys[ownPrivateAddress]!!.containsKey(sessionKeyIdHex))
            val keyData = store.sessionKeys[ownPrivateAddress]!![sessionKeyIdHex]!!
            assertEquals(
                sessionKeyGeneration.privateKey.encoded.asList(),
                keyData.privateKeyDer.asList()
            )
        }

        @Test
        fun `Key should be unbound by default`() = runBlockingTest {
            val store = MockPrivateKeyStore()

            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
            )

            val keyData = store.sessionKeys[ownPrivateAddress]!![sessionKeyIdHex]!!
            assertNull(keyData.peerPrivateAddress)
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

            val keyData = store.sessionKeys[ownPrivateAddress]!![sessionKeyIdHex]!!
            assertEquals(peerPrivateAddress, keyData.peerPrivateAddress)
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
        fun `Keys bound to another peer should not be returned`() = runBlockingTest {
            val store = MockPrivateKeyStore()
            store.saveSessionKey(
                sessionKeyGeneration.privateKey,
                sessionKeyGeneration.sessionKey.keyId,
                ownPrivateAddress,
                peerPrivateAddress
            )
            val invalidPeerPrivateAddress = "not $peerPrivateAddress"

            val exception = assertThrows<MissingKeyException> {
                store.retrieveSessionKey(
                    sessionKeyGeneration.sessionKey.keyId,
                    ownPrivateAddress,
                    invalidPeerPrivateAddress
                )
            }

            assertEquals(
                "Session key is bound to $peerPrivateAddress (not $invalidPeerPrivateAddress)",
                exception.message
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
    }
}
