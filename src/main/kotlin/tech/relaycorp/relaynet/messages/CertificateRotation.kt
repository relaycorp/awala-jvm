package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CertificateRotation(val subjectCertificate: Certificate, val chain: List<Certificate>) {
    fun serialize(): ByteArray {
        val chainSequence = ASN1Utils.makeSequence(
            chain.map { DEROctetString(it.serialize()) },
            false
        )
        val sequence = ASN1Utils.serializeSequence(
            listOf(
                DEROctetString(subjectCertificate.serialize()),
                chainSequence
            ),
            false
        )
        return FORMAT_SIGNATURE + sequence
    }

    companion object {
        private const val concreteMessageType: Byte = 0x10
        private const val concreteMessageVersion: Byte = 0
        internal val FORMAT_SIGNATURE = byteArrayOf(
            *"Relaynet".toByteArray(),
            concreteMessageType,
            concreteMessageVersion
        )
    }
}
