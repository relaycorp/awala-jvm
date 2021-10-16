package tech.relaycorp.relaynet

import org.bouncycastle.asn1.ASN1ObjectIdentifier

internal object OIDs {
    private val RELAYCORP: ASN1ObjectIdentifier =
        ASN1ObjectIdentifier("0.4.0.127.0.17").intern()
    private val AWALA = RELAYCORP.branch("0").intern()

    private val AWALA_PKI = AWALA.branch("1").intern()
    val ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER : ASN1ObjectIdentifier =
        AWALA_PKI.branch("0")

    private val PRIVATE_NODE_REGISTRATION_PREFIX = AWALA.branch("2").intern()
    val PNRA: ASN1ObjectIdentifier =
        PRIVATE_NODE_REGISTRATION_PREFIX.branch("0").intern()
    val PNRA_COUNTERSIGNATURE: ASN1ObjectIdentifier =
        PRIVATE_NODE_REGISTRATION_PREFIX.branch("1").intern()

    val DETACHED_SIGNATURE: ASN1ObjectIdentifier = AWALA.branch("3").intern()
}
