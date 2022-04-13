package tech.relaycorp.relaynet.pki

import tech.relaycorp.relaynet.wrappers.x509.Certificate

data class CertificationPath(
    val leafCertificate: Certificate,
    val chain: List<Certificate>
)
