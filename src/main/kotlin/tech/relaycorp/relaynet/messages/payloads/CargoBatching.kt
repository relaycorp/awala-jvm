@file:JvmName("CargoMessageBatching")

package tech.relaycorp.relaynet.messages.payloads

import java.time.ZonedDateTime
import java.util.Collections
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.ramf.EncryptedRAMFMessage

private const val MAX_BATCH_LENGTH =
    EncryptedRAMFMessage.MAX_PAYLOAD_PLAINTEXT_LENGTH - CargoMessage.DER_TL_OVERHEAD_OCTETS

/**
 * Serialization and expiry date of a message to be encapsulated in a cargo message set.
 *
 * @throws InvalidMessageException if `cargoMessageSerialized` is longer than
 *   [CargoMessage.MAX_LENGTH]
 */
@Suppress("ArrayInDataClass")
data class CargoMessageWithExpiry(
    val cargoMessageSerialized: ByteArray,
    val expiryDate: ZonedDateTime
) {
    init {
        if (CargoMessage.MAX_LENGTH < cargoMessageSerialized.size) {
            throw InvalidMessageException(
                "Message must not be longer than ${CargoMessage.MAX_LENGTH} octets " +
                    "(got ${cargoMessageSerialized.size})"
            )
        }
    }
}

/**
 * Serialization and expiry date of a cargo message set.
 */
data class CargoMessageSetWithExpiry(
    val cargoMessageSet: CargoMessageSet,
    val latestMessageExpiryDate: ZonedDateTime
)

/**
 * Batch as many messages together as possible without exceeding the payload length limit on
 * individual cargoes.
 *
 * If all messages can be encapsulated in the same cargo message set, they will be. Otherwise,
 * multiple cargo message sets will be generated. The output will be empty if the input is
 * empty too.
 */
suspend fun Sequence<CargoMessageWithExpiry>.batch(): Sequence<CargoMessageSetWithExpiry> =
    sequence {
        val currentBatch = mutableListOf<ByteArray>()
        var currentBatchExpiry: ZonedDateTime? = null
        var currentBatchAvailableOctets = MAX_BATCH_LENGTH

        this@batch.forEach { messageWithExpiry ->
            val messageTlvLength =
                CargoMessage.DER_TL_OVERHEAD_OCTETS + messageWithExpiry.cargoMessageSerialized.size
            val messageFitsInCurrentBatch = messageTlvLength <= currentBatchAvailableOctets
            if (!messageFitsInCurrentBatch) {
                val cargoMessageSet = CargoMessageSet(currentBatch.toTypedArray())
                yield(CargoMessageSetWithExpiry(cargoMessageSet, currentBatchExpiry!!))

                currentBatch.clear()
                currentBatchExpiry = null
                currentBatchAvailableOctets = MAX_BATCH_LENGTH
            }

            currentBatch.add(messageWithExpiry.cargoMessageSerialized)
            currentBatchAvailableOctets -= messageTlvLength

            currentBatchExpiry = currentBatchExpiry ?: messageWithExpiry.expiryDate
            currentBatchExpiry =
                Collections.max(listOf(currentBatchExpiry, messageWithExpiry.expiryDate))
        }

        if (currentBatch.isNotEmpty()) {
            val cargoMessageSet = CargoMessageSet(currentBatch.toTypedArray())
            yield(CargoMessageSetWithExpiry(cargoMessageSet, currentBatchExpiry as ZonedDateTime))
        }
    }
