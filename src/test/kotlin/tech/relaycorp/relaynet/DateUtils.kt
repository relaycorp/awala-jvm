package tech.relaycorp.relaynet

import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.test.assertTrue

fun assertDateIsAlmostNow(date: ZonedDateTime) {
    val now = ZonedDateTime.now(ZoneId.of(date.zone.id))
    val secondsAgo = now.minusSeconds(2)

    assertTrue(secondsAgo < date)
    assertTrue(date <= now)
}
