package tech.relaycorp.relaynet.messages.payloads

import org.junit.jupiter.api.assertThrows
import kotlin.test.Test

internal class ServiceMessageTest {
    @Test
    fun deserialize() {
        // TODO
        assertThrows<NotImplementedError> { ServiceMessage().serialize() }
    }
}
