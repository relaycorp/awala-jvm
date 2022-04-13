package tech.relaycorp.relaynet.pki

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CertificationPath(
    val leafCertificate: Certificate,
    val certificateAuthorities: List<Certificate>
) {
    fun serialize(): ByteArray {
        val leafCertificateASN1 = DEROctetString(leafCertificate.serialize())
        val casASN1 = ASN1Utils.makeSequence(
            certificateAuthorities.map { DEROctetString(it.serialize()) },
            true
        )
        return ASN1Utils.serializeSequence(listOf(leafCertificateASN1, casASN1), false)
    }

    companion object {
        @Throws(CertificationPathException::class)
        fun deserialize(serialization: ByteArray): CertificationPath {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw CertificationPathException("Path is not a valid DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw CertificationPathException("Path sequence should have at least 2 items")
            }

            val leafCertificateASN1 = ASN1Utils.getOctetString(sequence.first())
            val leafCertificate = try {
                Certificate.deserialize(leafCertificateASN1.octets)
            } catch (exc: CertificateException) {
                throw CertificationPathException("Leaf certificate is malformed", exc)
            }

            val casSequence = try {
                DERSequence.getInstance(sequence[1], false)
            } catch (exc: IllegalStateException) {
                throw CertificationPathException("Chain is malformed", exc)
            }
            val certificateAuthorities = try {
                casSequence.toList()
                    .map { DEROctetString.getInstance(it).octets }
                    .map { Certificate.deserialize(it) }
            } catch (exc: CertificateException) {
                throw CertificationPathException("Chain contains malformed certificate", exc)
            } catch (exc: IllegalArgumentException) {
                throw CertificationPathException("Chain contains non-OCTET STRING item", exc)
            }

            return CertificationPath(leafCertificate, certificateAuthorities)
        }
    }
}
