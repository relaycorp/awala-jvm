package tech.relaycorp.relaynet

import java.time.ZoneId
import java.util.Date

internal fun dateToZonedDateTime(date: Date) = date.toInstant().atZone(
    ZoneId.systemDefault()
)
