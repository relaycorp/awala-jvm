package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZonedDateTime

object DummyCertPath {
    private val tomorrow = ZonedDateTime.now().plusDays(1)

    private val publicGatewayKeyPair = generateRSAKeyPair()
    val publicGatewayCert = issueGatewayCertificate(
        publicGatewayKeyPair.public,
        publicGatewayKeyPair.private,
        tomorrow
    )
    private val privateGatewayKeyPair = generateRSAKeyPair()
    val privateGatewayCert = issueGatewayCertificate(
        privateGatewayKeyPair.public,
        publicGatewayKeyPair.private,
        tomorrow,
        publicGatewayCert
    )
    private val endpointKeyPair = generateRSAKeyPair()
    val endpointCert = issueEndpointCertificate(
        endpointKeyPair.public,
        privateGatewayKeyPair.private,
        tomorrow,
        privateGatewayCert
    )
    val pdaGranteeKeyPair = generateRSAKeyPair()
    val pdaGranteeCert = issueParcelDeliveryAuthorization(
        pdaGranteeKeyPair.public,
        endpointKeyPair.private,
        tomorrow,
        endpointCert
    )
}
