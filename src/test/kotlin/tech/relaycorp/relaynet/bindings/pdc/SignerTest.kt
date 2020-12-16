package tech.relaycorp.relaynet.bindings.pdc

import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.PDACertPath
import tech.relaycorp.relaynet.KeyPairSet
import kotlin.test.assertEquals

class SignerTest {
    private val plaintext = "The plaintext".toByteArray()
    private val keyPair = KeyPairSet.PRIVATE_ENDPOINT
    private val certificate = PDACertPath.PRIVATE_ENDPOINT
    private val signer = Signer(certificate, keyPair.private)

    @Test
    fun `Signature should be valid`() {
        val signatureType = DetachedSignatureType.NONCE
        val serialization = signer.sign(plaintext, signatureType)

        signatureType.verify(serialization, plaintext, listOf(PDACertPath.PRIVATE_GW))
    }

    @Test
    fun `Signer certificate should be exposed`() {
        assertEquals(certificate, signer.certificate)
    }
}
