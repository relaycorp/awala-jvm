package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZonedDateTime

fun sha256(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}

fun sha256Hex(input: ByteArray) = sha256(input).joinToString("") { "%02x".format(it) }

fun issueStubCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate? = null,
    isCA: Boolean = false
): Certificate {
    return Certificate.issue(
        "the subject for the stub cert",
        subjectPublicKey,
        issuerPrivateKey,
        ZonedDateTime.now().plusDays(1),
        isCA = isCA,
        issuerCertificate = issuerCertificate
    )
}
