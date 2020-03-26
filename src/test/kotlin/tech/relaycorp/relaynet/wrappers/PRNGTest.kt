package tech.relaycorp.relaynet.wrappers

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.RepeatedTest
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PRNGTest {
    @Nested
    inner class GenerateRandomBigInteger {
        @RepeatedTest(8) // Because the bitLength of the value is variable
        fun `Output should be 64 bit unsigned number`() {
            val value = generateRandomBigInteger()

            assertEquals(1, value.signum(), "Value should be positive")
            assertTrue(
                value.bitLength() in 48..64,
                "Value should be between 48 and 64 bits; got ${value.bitLength()}"
            )
        }
    }
}
