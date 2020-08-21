package tech.relaycorp.relaynet.bindings.pdc

import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.issueEndpointCertificate
import tech.relaycorp.relaynet.messages.control.NonceSignature
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZonedDateTime
import kotlin.test.assertEquals

class NonceSignerTest {
    private val nonce = "The nonce".toByteArray()
    private val keyPair = generateRSAKeyPair()
    private val certificate = issueEndpointCertificate(
        keyPair.public,
        keyPair.private,
        ZonedDateTime.now().plusDays(1)
    )
    private val signer = NonceSigner(certificate, keyPair.private)

    @Test
    fun `Nonce should be honored`() {
        val serialization = signer.sign(nonce)

        val signature = NonceSignature.deserialize(serialization)
        assertEquals(nonce.asList(), signature.nonce.asList())
    }

    @Test
    fun `Signer certificate should be honored`() {
        val serialization = signer.sign(nonce)

        val signature = NonceSignature.deserialize(serialization)
        assertEquals(certificate, signature.signerCertificate)
    }
}
