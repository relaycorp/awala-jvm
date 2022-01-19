package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.wrappers.x509.Certificate

data class CertificationPath(
    val leafCertificate: Certificate,
    val chain: List<Certificate>
)