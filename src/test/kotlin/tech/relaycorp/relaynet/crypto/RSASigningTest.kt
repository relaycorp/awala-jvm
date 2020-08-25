package tech.relaycorp.relaynet.crypto

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RSASigningTest {
    private val plaintext = "the plaintext".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Sign {
        @Test
        fun `The plaintext should be signed with RSA-PSS, SHA-256 and MGF1`() {
            val ciphertext = RSASigning.sign(plaintext, keyPair.private)

            val signature: Signature = makeSignature()
            signature.initVerify(keyPair.public)
            signature.update(plaintext)

            assertTrue(signature.verify(ciphertext))
        }
    }

    @Nested
    inner class Verify {
        @Test
        fun `Invalid plaintexts should be refused`() {
            val anotherPlaintext = byteArrayOf(*plaintext, 1)
            val ciphertext = RSASigning.sign(anotherPlaintext, keyPair.private)

            assertFalse(RSASigning.verify(ciphertext, keyPair.public, plaintext))
        }

        @Test
        fun `Algorithms other than RSA-PSS with SHA-256 and MGF1 should be refused`() {
            val signature: Signature = Signature.getInstance("SHA256withRSA", BC_PROVIDER)
            signature.initSign(keyPair.private)
            signature.update(plaintext)
            val ciphertext = signature.sign()

            assertFalse(RSASigning.verify(ciphertext, keyPair.public, plaintext))
        }

        @Test
        fun `Valid signatures should be accepted`() {
            val ciphertext = RSASigning.sign(plaintext, keyPair.private)

            assertTrue(RSASigning.verify(ciphertext, keyPair.public, plaintext))
        }
    }

    private fun makeSignature(): Signature {
        val signature = Signature.getInstance("SHA256withRSA/PSS", BC_PROVIDER)
        val pssParameterSpec = PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
        signature.setParameter(pssParameterSpec)
        return signature
    }
}
