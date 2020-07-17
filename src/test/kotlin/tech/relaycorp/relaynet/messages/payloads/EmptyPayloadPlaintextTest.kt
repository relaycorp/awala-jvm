package tech.relaycorp.relaynet.messages.payloads

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.ramf.RAMFException
import kotlin.test.Test
import kotlin.test.assertEquals

internal class EmptyPayloadPlaintextTest {
    @Nested
    inner class Serialize {
        @Test
        fun `An empty ByteArray should be returned`() {
            val payloadPlaintext = EmptyPayloadPlaintext()

            assertEquals(0, payloadPlaintext.serialize().size)
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `An empty buffer should be accepted`() {
            EmptyPayloadPlaintext.deserialize(ByteArray(0))
        }

        @Test
        fun `An error should be thrown if buffer is not empty`() {
            val exception = assertThrows<RAMFException> {
                EmptyPayloadPlaintext.deserialize("a".toByteArray())
            }

            assertEquals("Payload is not empty", exception.message)
        }
    }
}
