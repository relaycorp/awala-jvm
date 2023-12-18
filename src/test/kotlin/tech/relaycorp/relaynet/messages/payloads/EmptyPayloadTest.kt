package tech.relaycorp.relaynet.messages.payloads

import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.ramf.RAMFException

internal class EmptyPayloadTest {
    @Nested
    inner class Serialize {
        @Test
        fun `An empty ByteArray should be returned`() {
            val payload = EmptyPayload()

            assertEquals(0, payload.serializePlaintext().size)
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `An empty buffer should be accepted`() {
            EmptyPayload.deserialize(ByteArray(0))
        }

        @Test
        fun `An error should be thrown if buffer is not empty`() {
            val exception =
                assertThrows<RAMFException> {
                    EmptyPayload.deserialize("a".toByteArray())
                }

            assertEquals("Payload is not empty", exception.message)
        }
    }
}
