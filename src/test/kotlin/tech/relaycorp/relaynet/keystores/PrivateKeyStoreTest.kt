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
}
