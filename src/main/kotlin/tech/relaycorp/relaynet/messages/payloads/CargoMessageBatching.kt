@file:JvmName("CargoMessageBatching")

package tech.relaycorp.relaynet.messages.payloads

import java.time.ZonedDateTime

data class CargoMessageWithExpiry(
    val getMessageSerialized: () -> ByteArray,
    val expiryDate: ZonedDateTime
)

data class CargoMessageSetWithExpiry(
    val cargoMessageSet: CargoMessageSet,
    val expiryDate: ZonedDateTime
)

fun Sequence<CargoMessageWithExpiry>.batch(): Sequence<CargoMessageSetWithExpiry> = TODO()
