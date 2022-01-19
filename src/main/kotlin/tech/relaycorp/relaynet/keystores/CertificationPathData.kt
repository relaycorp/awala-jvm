package tech.relaycorp.relaynet.keystores

data class CertificationPathData(
    val leafCertificate: CertificateData,
    val chain: List<CertificateData>
)