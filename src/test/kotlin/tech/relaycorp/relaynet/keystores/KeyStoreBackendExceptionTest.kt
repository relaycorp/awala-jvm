package tech.relaycorp.relaynet.keystores

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

class KeyStoreBackendExceptionTest {
    @Test
    fun `No cause should be set if absent`() {
        val exception = KeyStoreBackendException("whoops")

        assertNull(exception.cause)
    }

    @Test
    fun `Cause should be honored if present`() {
        val initialException = Exception("oh noes")
        val exception = KeyStoreBackendException("whoops", initialException)

        assertEquals(initialException, exception.cause)
    }
}
