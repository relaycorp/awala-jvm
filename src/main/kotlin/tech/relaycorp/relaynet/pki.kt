@file:JvmName("PKI")

package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

fun issueGatewayCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate? = null,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate {
    val privateAddress = "0${getSHA256DigestHex(subjectPublicKey.encoded)}"
    val isSelfIssued = issuerCertificate == null
    return Certificate.issue(
        privateAddress,
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        true,
        if (isSelfIssued) 2 else 1,
        validityStartDate
    )
}
