package tech.relaycorp.relaynet.pki

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CertificationPath(
    val leafCertificate: Certificate,
    val chain: List<Certificate>
) {
    fun serialize(): ByteArray {
        val leafCertificateASN1 = DEROctetString(leafCertificate.serialize())
        val chainASN1 = ASN1Utils.makeSequence(chain.map { DEROctetString(it.serialize()) }, false)
        return ASN1Utils.serializeSequence(listOf(leafCertificateASN1, chainASN1), false)
    }
}
