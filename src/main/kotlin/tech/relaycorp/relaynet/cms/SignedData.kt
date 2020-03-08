package tech.relaycorp.relaynet.cms

import java.security.cert.Certificate

@Throws(SignedDataException::class)
fun sign(): ByteArray {
    throw NotImplementedError()
}

data class SignatureVerification(
    val signerCertificate: Certificate,
    val attachedCertificates: Array<Certificate>
)

@Throws(SignedDataException::class)
fun verifySignature(): SignatureVerification {
    throw NotImplementedError()
}
