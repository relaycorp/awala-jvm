package tech.relaycorp.relaynet.utils

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.issueDeliveryAuthorization
import tech.relaycorp.relaynet.issueEndpointCertificate
import tech.relaycorp.relaynet.issueGatewayCertificate

/**
 * Full certification path from a public gateway to a PDA.
 */
object PDACertPath {
    private val now: ZonedDateTime = ZonedDateTime.now()
    private val twoSecondsAgo = now.minusSeconds(2)
    private val tomorrow = now.plusDays(1)

    val PUBLIC_GW = issueGatewayCertificate(
        KeyPairSet.PUBLIC_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        tomorrow,
        validityStartDate = twoSecondsAgo
    )
    val PRIVATE_GW = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        tomorrow,
        PUBLIC_GW,
        twoSecondsAgo
    )
    val PRIVATE_ENDPOINT = issueEndpointCertificate(
        KeyPairSet.PRIVATE_ENDPOINT.public,
        KeyPairSet.PRIVATE_GW.private,
        tomorrow,
        PRIVATE_GW,
        twoSecondsAgo
    )
    val PDA = issueDeliveryAuthorization(
        KeyPairSet.PDA_GRANTEE.public,
        KeyPairSet.PRIVATE_ENDPOINT.private,
        tomorrow,
        PRIVATE_ENDPOINT,
        twoSecondsAgo
    )
}
