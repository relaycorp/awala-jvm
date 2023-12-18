package tech.relaycorp.relaynet.nodes

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.MockSessionPublicKeyStore

class EndpointManagerTest {
    private val privateKeyStore = MockPrivateKeyStore()
    private val sessionPublicKeyStore = MockSessionPublicKeyStore()

    @Nested
    inner class Constructor {
        @Test
        fun `Default crypto algorithms should be used by default`() {
            val endpointManager = EndpointManager(privateKeyStore, sessionPublicKeyStore)

            assertEquals(NodeCryptoOptions(), endpointManager.cryptoOptions)
        }

        @Test
        fun `Custom crypto algorithms should be honored`() {
            val options =
                NodeCryptoOptions(
                    ECDHCurve.P521,
                    SymmetricCipher.AES_256,
                    HashingAlgorithm.SHA512,
                )
            val endpointManager = EndpointManager(privateKeyStore, sessionPublicKeyStore, options)

            assertEquals(options, endpointManager.cryptoOptions)
        }
    }
}
