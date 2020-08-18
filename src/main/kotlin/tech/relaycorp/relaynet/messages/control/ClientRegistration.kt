package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

/**
 * Client registration with a private or public gateway.
 *
 * When the client is a private endpoint, the server must be a private gateway. When the client
 * is a private gateway, the server must be a public gateway.
 *
 * @param clientCertificate The certificate of the private endpoint/gateway
 * @param serverCertificate The certificate of the gateway acting as server
 */
class ClientRegistration(val clientCertificate: Certificate, val serverCertificate: Certificate) {
    /**
     * Serialize registration.
     */
    fun serialize(): ByteArray {
        val clientCertificateASN1 = DEROctetString(clientCertificate.serialize())
        val serverCertificateASN1 = DEROctetString(serverCertificate.serialize())
        return ASN1Utils.serializeSequence(
            arrayOf(clientCertificateASN1, serverCertificateASN1),
            false
        )
    }

    companion object {
        /**
         * Deserialize registration.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): ClientRegistration {
            val sequence = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Client registration is not a DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw InvalidMessageException(
                    "Client registration sequence should have at least two items (got " +
                        "${sequence.size})"
                )
            }
            val clientCertificate = try {
                deserializeCertificate(sequence[0])
            } catch (exc: CertificateException) {
                throw InvalidMessageException(
                    "Client registration contains invalid client certificate",
                    exc
                )
            }
            val serverCertificate = try {
                deserializeCertificate(sequence[1])
            } catch (exc: CertificateException) {
                throw InvalidMessageException(
                    "Client registration contains invalid server certificate",
                    exc
                )
            }
            return ClientRegistration(clientCertificate, serverCertificate)
        }

        @Throws(CertificateException::class)
        private fun deserializeCertificate(asn1Object: ASN1TaggedObject): Certificate {
            val certificateASN1 = ASN1Utils.getOctetString(asn1Object)
            return Certificate.deserialize(certificateASN1.octets)
        }
    }
}
