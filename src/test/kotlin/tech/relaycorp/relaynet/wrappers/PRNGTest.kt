package tech.relaycorp.relaynet.wrappers

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class PRNGTest {
    @Nested
    inner class GenerateRandomBigInteger {
        @Test
        fun `Output should be 64 bit number`() {
            val value = generateRandomBigInteger()

            assert(value.bitLength() in 61..64)
        }
    }
}
