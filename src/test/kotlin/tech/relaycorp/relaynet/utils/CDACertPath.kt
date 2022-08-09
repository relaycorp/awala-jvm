package tech.relaycorp.relaynet.utils

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.issueDeliveryAuthorization
import tech.relaycorp.relaynet.issueGatewayCertificate

/**
 * Full certification path from a private gateway to a public one.
 */
object CDACertPath {
    private val now: ZonedDateTime = ZonedDateTime.now()
    private val twoSecondsAgo = now.minusSeconds(2)
    private val tomorrow = now.plusDays(1)

    val PRIVATE_GW = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.INTERNET_GW.private,
        tomorrow,
        validityStartDate = twoSecondsAgo
    )
    val INTERNET_GW = issueDeliveryAuthorization(
        KeyPairSet.INTERNET_GW.public,
        KeyPairSet.INTERNET_GW.private,
        tomorrow,
        PRIVATE_GW,
        validityStartDate = twoSecondsAgo
    )
}
