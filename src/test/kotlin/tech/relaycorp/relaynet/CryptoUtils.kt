package tech.relaycorp.relaynet

import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.time.LocalDateTime
import tech.relaycorp.relaynet.wrappers.x509.Certificate

fun sha256(input: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(input)
}

fun issueStubCertificate(
    subjectPublicKey: PublicKey,
    issuerPrivateKey: PrivateKey,
    issuerCertificate: Certificate? = null,
    isCA: Boolean = false
): Certificate {
    return Certificate.issue(
        "the subject for the stub cert",
        issuerPrivateKey,
        subjectPublicKey,
        LocalDateTime.now().plusDays(1),
        isCA = isCA,
        issuerCertificate = issuerCertificate
    )
}
