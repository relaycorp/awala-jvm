package tech.relaycorp.relaynet

import org.bouncycastle.asn1.ASN1ObjectIdentifier

internal object OIDs {
    private val RELAYCORP: ASN1ObjectIdentifier =
        ASN1ObjectIdentifier("0.4.0.127.0.17").intern()
    private val RELAYNET = RELAYCORP.branch("0").intern()

    private val PRIVATE_NODE_REGISTRATION_PREFIX = RELAYNET.branch("2").intern()
    val PNRA: ASN1ObjectIdentifier =
        PRIVATE_NODE_REGISTRATION_PREFIX.branch("0").intern()
    val PNRA_COUNTERSIGNATURE: ASN1ObjectIdentifier =
        PRIVATE_NODE_REGISTRATION_PREFIX.branch("1").intern()

    val NONCE_SIGNATURE: ASN1ObjectIdentifier = RELAYNET.branch("3").intern()
}
