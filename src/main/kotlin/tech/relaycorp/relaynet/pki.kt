@file:JvmName("PKI")

package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

/**
 * Issue Relaynet PKI certificate to a private or public gateway.
 *
 * @param subjectPublicKey The public key of the subject
 * @param issuerPrivateKey The private key of the issuer
 * @param validityEndDate The end date of the certificate to be issued
 * @param issuerCertificate The certificate of the issuer, unless issuing a self-signed certificate
 * @param validityStartDate The start date of the certificate to be issued
 */
fun issueGatewayCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate? = null,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate {
    val isSelfIssued = issuerCertificate == null
    return Certificate.issue(
        computePrivateAddress(subjectPublicKey),
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        true,
        if (isSelfIssued) 2 else 1,
        validityStartDate
    )
}

fun issueEndpointCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate? = null,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate {
    return Certificate.issue(
        computePrivateAddress(subjectPublicKey),
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        true,
        0,
        validityStartDate
    )
}

fun issueParcelDeliveryAuthorization(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate = Certificate.issue(
    computePrivateAddress(subjectPublicKey),
    subjectPublicKey,
    issuerPrivateKey,
    validityEndDate,
    issuerCertificate,
    false,
    0,
    validityStartDate
)

private fun computePrivateAddress(subjectPublicKey: PublicKey) =
    "0${getSHA256DigestHex(subjectPublicKey.encoded)}"
