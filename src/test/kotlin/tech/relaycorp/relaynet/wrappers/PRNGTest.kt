package tech.relaycorp.relaynet.wrappers

import kotlin.test.assertNotNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class PRNGTest {
    @Nested
    inner class GenerateRandom64BitValue {
        @Test
        fun `Random long number should be output`() {
            val value = generateRandom64BitValue()

            assertNotNull(value)
        }
    }
}
