package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

/**
 * Private node registration with its private or public gateway.
 *
 * When the node is a private endpoint, the gateway must be private. When the node is a private
 * gateway, the gateway must be public.
 *
 * @param privateNodeCertificate The certificate of the private node
 * @param gatewayCertificate The certificate of the gateway acting as server
 */
class PrivateNodeRegistration(
    val privateNodeCertificate: Certificate,
    val gatewayCertificate: Certificate
) {
    /**
     * Serialize registration.
     */
    fun serialize(): ByteArray {
        val nodeCertificateASN1 = DEROctetString(privateNodeCertificate.serialize())
        val gatewayCertificateASN1 = DEROctetString(gatewayCertificate.serialize())
        return ASN1Utils.serializeSequence(
            listOf(nodeCertificateASN1, gatewayCertificateASN1),
            false
        )
    }

    companion object {
        /**
         * Deserialize registration.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): PrivateNodeRegistration {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Node registration is not a DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw InvalidMessageException(
                    "Node registration sequence should have at least two items (got " +
                        "${sequence.size})"
                )
            }
            val nodeCertificate = try {
                deserializeCertificate(sequence[0])
            } catch (exc: CertificateException) {
                throw InvalidMessageException(
                    "Node registration contains invalid node certificate",
                    exc
                )
            }
            val gatewayCertificate = try {
                deserializeCertificate(sequence[1])
            } catch (exc: CertificateException) {
                throw InvalidMessageException(
                    "Node registration contains invalid gateway certificate",
                    exc
                )
            }
            return PrivateNodeRegistration(nodeCertificate, gatewayCertificate)
        }

        @Throws(CertificateException::class)
        private fun deserializeCertificate(asn1Object: ASN1TaggedObject): Certificate {
            val certificateASN1 = ASN1Utils.getOctetString(asn1Object)
            return Certificate.deserialize(certificateASN1.octets)
        }
    }
}
