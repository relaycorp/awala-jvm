package tech.relaycorp.relaynet

import org.bouncycastle.asn1.ASN1ObjectIdentifier

internal object OIDs {
    private val RELAYCORP: ASN1ObjectIdentifier =
        ASN1ObjectIdentifier("0.4.0.127.0.17").intern()
    private val RELAYNET = RELAYCORP.branch("0").intern()

    private val CLIENT_REGISTRATION_PREFIX = RELAYNET.branch("2").intern()
    val CRA: ASN1ObjectIdentifier =
        CLIENT_REGISTRATION_PREFIX.branch("0").intern()
    val CRA_COUNTERSIGNATURE: ASN1ObjectIdentifier =
        CLIENT_REGISTRATION_PREFIX.branch("1").intern()
}
