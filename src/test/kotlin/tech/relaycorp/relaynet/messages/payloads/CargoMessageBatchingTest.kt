package tech.relaycorp.relaynet.messages.payloads

import org.junit.jupiter.api.Disabled
import kotlin.test.Test

class CargoMessageBatchingTest {
    @Test
    @Disabled
    fun `Zero messages should result in zero batches`() {
    }

    @Test
    @Disabled
    fun `A single message should result in one batch`() {
    }

    @Test
    @Disabled
    fun `Multiple small messages should be put in the same batch`() {
    }

    @Test
    @Disabled
    fun `Messages should be put into as few batches as possible`() {
    }

    @Test
    @Disabled
    fun `Messages exceeding the max per-message size should be refused`() {
    }

    @Test
    @Disabled
    fun `A message with the largest possible length should be included`() {
    }

    @Test
    @Disabled
    fun `Messages collectively reaching max length should be placed together`() {
    }

    @Test
    @Disabled
    fun `Expiry date of batch should be that of its message with latest expiry`() {
    }
}
