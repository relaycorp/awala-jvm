package tech.relaycorp.relaynet.pki

import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.Certificate as BCCertificate
import org.bouncycastle.cert.X509CertificateHolder
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CertificationPath(
    val leafCertificate: Certificate,
    val certificateAuthorities: List<Certificate>
) {
    @Throws(CertificationPathException::class)
    fun validate() {
        if (certificateAuthorities.isEmpty()) {
            throw CertificationPathException("There are no CAs")
        }

        val rootCA = certificateAuthorities.last()
        val intermediateCAs = certificateAuthorities.subList(0, certificateAuthorities.size)
        try {
            leafCertificate.getCertificationPath(intermediateCAs, listOf(rootCA))
        } catch (exc: CertificateException) {
            throw CertificationPathException("Certification path is invalid", exc)
        }
    }

    internal fun encode(): DERSequence {
        val leafCertificateASN1 = leafCertificate.encode()
        val casASN1 = ASN1Utils.makeSequence(
            certificateAuthorities.map { it.encode() },
            true
        )
        return ASN1Utils.makeSequence(listOf(leafCertificateASN1, casASN1), false)
    }

    fun serialize(): ByteArray {
        val sequence = encode()
        return sequence.encoded
    }

    companion object {
        @Throws(CertificationPathException::class)
        fun deserialize(serialization: ByteArray): CertificationPath {
            val sequence = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw CertificationPathException("Path is not a valid DER sequence", exc)
            }
            return decode(sequence)
        }

        @Throws(CertificationPathException::class)
        internal fun decode(encoding: ASN1TaggedObject): CertificationPath {
            val sequence = try {
                DERSequence.getInstance(encoding, false)
            } catch (exc: IllegalStateException) {
                throw CertificationPathException(
                    "Serialisation is not an implicitly-tagged sequence",
                    exc
                )
            }
            return decode(sequence)
        }

        @Throws(CertificationPathException::class)
        private fun decode(sequence: ASN1Sequence): CertificationPath {
            if (sequence.size() < 2) {
                throw CertificationPathException("Path sequence should have at least 2 items")
            }

            val leafCertificateASN1 = try {
                BCCertificate.getInstance(sequence.getObjectAt(0) as ASN1TaggedObject, false)
            } catch (exc: IllegalStateException) {
                throw CertificationPathException("Leaf certificate is malformed", exc)
            }
            val leafCertificate = Certificate(X509CertificateHolder(leafCertificateASN1))

            val casSequence = try {
                DERSequence.getInstance(sequence.getObjectAt(1) as ASN1TaggedObject, false)
            } catch (exc: IllegalStateException) {
                throw CertificationPathException("Chain is malformed", exc)
            }
            val certificateAuthorities = try {
                casSequence.toList()
                    .map { BCCertificate.getInstance(it) }
                    .map { Certificate(X509CertificateHolder(it)) }
            } catch (exc: IllegalArgumentException) {
                throw CertificationPathException("Chain contains malformed certificate", exc)
            }

            return CertificationPath(leafCertificate, certificateAuthorities)
        }
    }
}
