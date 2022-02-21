package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CertificateRotation(subjectCertificate: Certificate, chain: List<Certificate>) {
    fun serialize(): ByteArray {
        TODO("Not yet implemented")
    }
}
