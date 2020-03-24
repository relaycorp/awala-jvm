package tech.relaycorp.relaynet.wrappers

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class KeysTest {
    @Nested
    inner class GenerateRSAKeyPair {
        @Test
        fun `Key pair should be returned when a valid modulus is passed`() {
            val keyPair = generateRSAKeyPair(4096)

            assert(keyPair.private is RSAPrivateKey)
            assertTrue(keyPair.private.toString().contains("4096 bits"), "DEBUG: ${keyPair.private}")

            assert(keyPair.public is RSAPublicKey)
            assert(keyPair.public.toString().contains("4096 bits"))
        }

        @Test
        fun `Modulus should be 2048 by default`() {
            val keyPair = generateRSAKeyPair()

            assert(keyPair.private.toString().contains("2048 bits"))

            assert(keyPair.public.toString().contains("2048 bits"))
        }

        @Test
        fun `Modulus should be 2048 or greater`() {
            val exception = assertThrows<KeyException> {
                generateRSAKeyPair(2047)
            }
            assertEquals(
                "Modulus should be at least 2048 (got 2047)",
                exception.message
            )
        }
    }
}
