package tech.relaycorp.relaynet.keystores

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.PDACertPath
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@ExperimentalCoroutinesApi
class PrivateKeyStoreTest {
    private val identityPrivateKey = KeyPairSet.PRIVATE_GW.private
    private val identityCertificate = PDACertPath.PRIVATE_GW

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
}
