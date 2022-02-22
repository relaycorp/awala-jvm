package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

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

        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): CertificateRotation {
            if (serialization.size < FORMAT_SIGNATURE.size) {
                throw InvalidMessageException("Message is too short to contain format signature")
            }
            val formatSignature = serialization.slice(FORMAT_SIGNATURE.indices)
            if (formatSignature != FORMAT_SIGNATURE.asList()) {
                throw InvalidMessageException(
                    "Format signature is not that of a CertificateRotation"
                )
            }

            val sequenceSerialized =
                serialization.sliceArray(FORMAT_SIGNATURE.size until serialization.size)
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(sequenceSerialized)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException(
                    "Serialization does not contain valid DER sequence",
                    exc
                )
            }
            if (sequence.size < 2) {
                throw InvalidMessageException("Sequence should contain at least 2 items")
            }

            val subjectCertificate = try {
                val certificateASN1 = ASN1Utils.getOctetString(sequence.first())
                Certificate.deserialize(certificateASN1.octets)
            } catch (exc: CertificateException) {
                throw InvalidMessageException("Subject certificate is malformed", exc)
            }

            val chainSequence = try {
                DERSequence.getInstance(sequence[1], false)
            } catch (exc: IllegalArgumentException) {
                throw InvalidMessageException("Chain is malformed", exc)
            }
            val chain = try {
                chainSequence.map { ASN1Utils.getOctetString(it as ASN1TaggedObject) }
                    .map { Certificate.deserialize(it.octets) }
            } catch (exc: CertificateException) {
                throw InvalidMessageException("Chain contains malformed certificate", exc)
            }

            return CertificateRotation(subjectCertificate, chain)
        }
    }
}
