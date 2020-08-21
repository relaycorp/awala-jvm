package tech.relaycorp.relaynet

import java.time.ZonedDateTime

object FullCertPath {
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
    val PDA = issueParcelDeliveryAuthorization(
        KeyPairSet.PDA_GRANTEE.public,
        KeyPairSet.PRIVATE_ENDPOINT.private,
        tomorrow,
        PRIVATE_ENDPOINT,
        twoSecondsAgo
    )
}
