package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSSignedData
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.parseDer

fun parseCmsSignedData(serialization: ByteArray): CMSSignedData {
    val contentInfo = ContentInfo.getInstance(
        parseDer(serialization)
    )
    return CMSSignedData(contentInfo)
}

val HASHING_ALGORITHM_OIDS = mapOf(
    HashingAlgorithm.SHA256 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
    HashingAlgorithm.SHA384 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
    HashingAlgorithm.SHA512 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3")
)
