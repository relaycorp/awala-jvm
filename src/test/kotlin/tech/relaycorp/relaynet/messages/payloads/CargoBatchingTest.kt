package tech.relaycorp.relaynet.messages.payloads

import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException

private val expiryDate = ZonedDateTime.now().plusDays(1)

@ExperimentalCoroutinesApi
class BatchTest {
    private val messageSerialized = "I'm a parcel. Pinky promise.".toByteArray()

    @Test
    fun `Zero messages should result in zero batches`() = runBlockingTest {
        val batches = emptySequence<CargoMessageWithExpiry>().batch()

        assertEquals(0, batches.count())
    }

    @Test
    fun `A single message should result in one batch`() = runBlockingTest {
        val batches = sequenceOf(CargoMessageWithExpiry(messageSerialized, expiryDate)).batch()

        assertEquals(1, batches.count())
        val cargoMessageSet = batches.first().cargoMessageSet
        assertEquals(1, cargoMessageSet.messages.size)
        assertEquals(messageSerialized.asList(), cargoMessageSet.messages.first().asList())
    }

    @Test
    fun `Multiple small messages should be put in the same batch`() = runBlockingTest {
        val message2Serialized = "I'm a PCA. *wink wink*".toByteArray()

        val batches = sequenceOf(
            CargoMessageWithExpiry(messageSerialized, expiryDate),
            CargoMessageWithExpiry(message2Serialized, expiryDate)
        ).batch()

        assertEquals(1, batches.count())
        val cargoMessageSet = batches.first().cargoMessageSet
        assertEquals(2, cargoMessageSet.messages.size)
        assertEquals(messageSerialized.asList(), cargoMessageSet.messages.first().asList())
        assertEquals(message2Serialized.asList(), cargoMessageSet.messages[1].asList())
    }

    @Test
    fun `Messages should be put into as few batches as possible`() = runBlockingTest {
        val octetsIn3Mib = 3145728
        val messageSerialized = "a".repeat(octetsIn3Mib).toByteArray()

        val batches = sequenceOf(
            CargoMessageWithExpiry(messageSerialized, expiryDate),
            CargoMessageWithExpiry(messageSerialized, expiryDate),
            CargoMessageWithExpiry(messageSerialized, expiryDate)
        ).batch()

        assertEquals(2, batches.count())
        val cargoMessageSet1 = batches.first().cargoMessageSet
        assertEquals(
            listOf(messageSerialized.asList(), messageSerialized.asList()),
            cargoMessageSet1.messages.map { it.asList() }
        )
        val cargoMessageSet2 = batches.last().cargoMessageSet
        assertEquals(1, cargoMessageSet2.messages.size)
        assertEquals(messageSerialized.asList(), cargoMessageSet2.messages.first().asList())
    }

    @Test
    fun `Messages collectively reaching the max length should be placed together`() =
        runBlockingTest {
            val halfLimit = CargoMessage.MAX_LENGTH / 2
            val message1Serialized = "a".repeat(halfLimit - 3).toByteArray()
            val message2Serialized = "a".repeat(halfLimit - 2).toByteArray()

            val batches = sequenceOf(
                CargoMessageWithExpiry(message1Serialized, expiryDate),
                CargoMessageWithExpiry(message2Serialized, expiryDate)
            ).batch()

            assertEquals(1, batches.count())
            val cargoMessageSet = batches.first().cargoMessageSet
            assertEquals(2, cargoMessageSet.messages.size)
            assertEquals(message1Serialized.asList(), cargoMessageSet.messages[0].asList())
            assertEquals(message2Serialized.asList(), cargoMessageSet.messages[1].asList())
        }

    @Test
    fun `Expiry date of batch should be that of its message with latest expiry`() =
        runBlockingTest {
            // Generate two batches where the expiry date of the former is that of its first
            // message, and the expiry date of the latter batch is that of its last message
            val messageSerialized = "a".repeat(CargoMessage.MAX_LENGTH / 2 - 3).toByteArray()
            val now = ZonedDateTime.now()
            val message1ExpiryDate = now.plusDays(2)
            val message2ExpiryDate = now.plusDays(1)
            val message3ExpiryDate = now.plusDays(3)
            val message4ExpiryDate = now.plusDays(4)

            val batches = sequenceOf(
                CargoMessageWithExpiry(messageSerialized, message1ExpiryDate),
                CargoMessageWithExpiry(messageSerialized, message2ExpiryDate),
                CargoMessageWithExpiry(messageSerialized, message3ExpiryDate),
                CargoMessageWithExpiry(messageSerialized, message4ExpiryDate)
            ).batch()

            assertEquals(2, batches.count())
            assertEquals(2, batches.first().cargoMessageSet.messages.size)
            assertEquals(message1ExpiryDate, batches.first().latestMessageExpiryDate)
            assertEquals(2, batches.last().cargoMessageSet.messages.size)
            assertEquals(message4ExpiryDate, batches.last().latestMessageExpiryDate)
        }
}

class CargoMessageWithExpiryTest {
    @Test
    fun `A message with the largest possible length should be accepted`() {
        val messageSerialized = "a".repeat(CargoMessage.MAX_LENGTH).toByteArray()

        CargoMessageWithExpiry(messageSerialized, expiryDate)
    }

    @Test
    fun `Messages exceeding the max per-message size should be refused`() {
        val messageSerialized = "a".repeat(CargoMessage.MAX_LENGTH + 1).toByteArray()

        val exception = assertThrows<InvalidMessageException> {
            CargoMessageWithExpiry(messageSerialized, expiryDate)
        }

        assertEquals(
            "Message must not be longer than ${CargoMessage.MAX_LENGTH} octets " +
                "(got ${messageSerialized.size})",
            exception.message
        )
    }
}
