package tech.relaycorp.relaynet.bindings.pdc

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class StreamingModeTest {
    @Test
    fun `Header name should adhere to spec`() {
        assertEquals("X-Relaynet-Streaming-Mode", StreamingMode.HEADER_NAME)
    }

    @Test
    fun `KeepAlive should adhere to spec`() {
        assertEquals("keep-alive", StreamingMode.KeepAlive.headerValue)
    }

    @Test
    fun `CloseUponCompletion should adhere to spec`() {
        assertEquals("close-upon-completion", StreamingMode.CloseUponCompletion.headerValue)
    }
}
