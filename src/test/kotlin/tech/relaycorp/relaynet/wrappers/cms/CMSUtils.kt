package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.cms.CMSSignedData
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.parseDer

fun parseCmsSignedData(serialization: ByteArray): CMSSignedData {
    val contentInfo = ContentInfo.getInstance(
        parseDer(serialization)
    )
    return CMSSignedData(contentInfo)
}

val HASHING_ALGORITHM_OIDS = mapOf(
    HashingAlgorithm.SHA256 to NISTObjectIdentifiers.id_sha256,
    HashingAlgorithm.SHA384 to NISTObjectIdentifiers.id_sha384,
    HashingAlgorithm.SHA512 to NISTObjectIdentifiers.id_sha512
)

val PAYLOAD_SYMMETRIC_ENC_ALGO_OIDS = mapOf(
    SymmetricEncryption.AES_128 to "2.16.840.1.101.3.4.1.2",
    SymmetricEncryption.AES_192 to "2.16.840.1.101.3.4.1.22",
    SymmetricEncryption.AES_256 to "2.16.840.1.101.3.4.1.42"
)
