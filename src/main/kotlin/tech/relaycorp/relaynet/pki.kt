@file:JvmName("PKI")

package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.privateAddress
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
 * @param issuerCertificate The certificate of the issuer, if the subject is a private gateway
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
        subjectPublicKey.privateAddress,
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        true,
        if (isSelfIssued) 2 else 1,
        validityStartDate
    )
}

/**
 * Issue Relaynet PKI certificate to a private or public endpoint.
 *
 * @param subjectPublicKey The public key of the subject
 * @param issuerPrivateKey The private key of the issuer
 * @param validityEndDate The end date of the certificate to be issued
 * @param issuerCertificate The certificate of the issuer, if the subject is a private endpoint
 * @param validityStartDate The start date of the certificate to be issued
 */
fun issueEndpointCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate? = null,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate {
    return Certificate.issue(
        subjectPublicKey.privateAddress,
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        true,
        0,
        validityStartDate
    )
}

/**
 * Issue a Parcel Delivery Authorization (PDA) to an endpoint.
 *
 * @param subjectPublicKey The public key of the grantee endpoint
 * @param issuerPrivateKey The private key of the granter endpoint
 * @param validityEndDate The end date of the certificate to be issued
 * @param issuerCertificate The certificate of the grantor
 * @param validityStartDate The start date of the certificate to be issued
 */
fun issueParcelDeliveryAuthorization(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    validityEndDate: ZonedDateTime,
    issuerCertificate: Certificate,
    validityStartDate: ZonedDateTime = ZonedDateTime.now()
): Certificate = Certificate.issue(
    subjectPublicKey.privateAddress,
    subjectPublicKey,
    issuerPrivateKey,
    validityEndDate,
    issuerCertificate,
    false,
    0,
    validityStartDate
)
