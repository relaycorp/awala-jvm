@file:JvmName("PKI")

package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.privateAddress
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZoneId
import java.time.ZonedDateTime

private const val MAX_DH_CERT_LENGTH_DAYS: Long = 60

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
 * Issue a Parcel Delivery Authorization (PDA) or Cargo Delivery Authorization (CDA).
 *
 * The issuer must be the *private* node wishing to receive messages from the subject. Both
 * nodes must be of the same type: Both gateways or both endpoints.
 *
 * @param subjectPublicKey The public key of the grantee node
 * @param issuerPrivateKey The private key of the granter node
 * @param validityEndDate The end date of the certificate to be issued
 * @param issuerCertificate The certificate of the grantor
 * @param validityStartDate The start date of the certificate to be issued
 */
fun issueDeliveryAuthorization(
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

/**
 * Issue an initial (EC)DH certificate to initiate a channel session.
 *
 * The subject must be the node initiating the session and the issue must be the recipient of the
 * initial message.
 */
fun issueInitialDHKeyCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate,
    validityEndDate: ZonedDateTime,
    validityStartDate: ZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC"))
): Certificate {
    val maxEndDate = validityStartDate.plusDays(MAX_DH_CERT_LENGTH_DAYS)
    if (maxEndDate < validityEndDate) {
        throw CertificateException(
            "DH key may not be valid for more than $MAX_DH_CERT_LENGTH_DAYS days"
        )
    }
    return Certificate.issue(
        issuerCertificate.commonName,
        subjectPublicKey,
        issuerPrivateKey,
        validityEndDate,
        issuerCertificate,
        false,
        0,
        validityStartDate
    )
}
