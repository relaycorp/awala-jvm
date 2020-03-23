package tech.relaycorp.relaynet.wrappers

import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class KeysTest {
    @Nested
    inner class GenerateRSAKeyPair {
        @Test
        fun `Key pair should be returned when a valid modulus is passed`() {
            val keyPair = generateRSAKeyPair(2048)
            assertNotNull(keyPair.private)
            assertNotNull(keyPair.public)
        }

        @Test
        fun `Modulus should be 2048 or greater`() {
            val exception = assertThrows<KeyException> {
                generateRSAKeyPair(2047)
            }
            assertEquals(
                "The modulus should be at least 2048 (got 2047)",
                exception.message
            )
        }
    }
}
