package tech.relaycorp.relaynet.wrappers

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

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

    @Nested
    inner class GenerateRandomOctets {
        @ParameterizedTest(name = "Output should contain {0} octets")
        @ValueSource(ints = [32, 64, 128])
        fun testLength(length: Int) {
            val value = generateRandomOctets(length)

            assertEquals(length, value.size)
        }
    }
}
