package tech.relaycorp.relaynet

import java.time.ZonedDateTime

object FullCertPath {
    private val tomorrow = ZonedDateTime.now().plusDays(1)

    val PUBLIC_GW = issueGatewayCertificate(
        KeyPairSet.PUBLIC_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        tomorrow
    )
    val PRIVATE_GW = issueGatewayCertificate(
        KeyPairSet.PRIVATE_GW.public,
        KeyPairSet.PUBLIC_GW.private,
        tomorrow,
        PUBLIC_GW
    )
    val PRIVATE_ENDPOINT = issueEndpointCertificate(
        KeyPairSet.PRIVATE_ENDPOINT.public,
        KeyPairSet.PRIVATE_GW.private,
        tomorrow,
        PRIVATE_GW
    )
    val PDA = issueParcelDeliveryAuthorization(
        KeyPairSet.PDA_GRANTEE.public,
        KeyPairSet.PRIVATE_ENDPOINT.private,
        tomorrow,
        PRIVATE_ENDPOINT
    )
}
