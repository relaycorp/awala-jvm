package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.DNS
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

/**
 * Private node registration with its gateway.
 *
 * When the node is a private endpoint, the gateway must be private. When the node is a private
 * gateway, the gateway must be public.
 *
 * @param privateNodeCertificate The certificate of the private node
 * @param gatewayCertificate The certificate of the gateway acting as server
 * @param gatewayInternetAddress The Internet address of the gateway
 * @param gatewaySessionKey The session key of the gateway acting as server
 */
class PrivateNodeRegistration(
    val privateNodeCertificate: Certificate,
    val gatewayCertificate: Certificate,
    val gatewayInternetAddress: String,
    val gatewaySessionKey: SessionKey? = null,
) {
    /**
     * Serialize registration.
     */
    fun serialize(): ByteArray {
        val nodeCertificateASN1 = DEROctetString(privateNodeCertificate.serialize())
        val gatewayCertificateASN1 = DEROctetString(gatewayCertificate.serialize())
        val gatewayInternetAddressASN1 = DERVisibleString(gatewayInternetAddress)
        val gatewaySessionKeyASN1 =
            if (gatewaySessionKey != null) {
                ASN1Utils.makeSequence(
                    listOf(
                        DEROctetString(gatewaySessionKey.keyId),
                        DEROctetString(gatewaySessionKey.publicKey.encoded),
                    ),
                    false,
                )
            } else {
                null
            }
        val rootSequence =
            listOf(
                nodeCertificateASN1,
                gatewayCertificateASN1,
                gatewayInternetAddressASN1,
            ) + listOfNotNull(gatewaySessionKeyASN1)
        return ASN1Utils.serializeSequence(rootSequence, false)
    }

    companion object {
        /**
         * Deserialize registration.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): PrivateNodeRegistration {
            val sequence =
                try {
                    ASN1Utils.deserializeHeterogeneousSequence(serialization)
                } catch (exc: ASN1Exception) {
                    throw InvalidMessageException("Node registration is not a DER sequence", exc)
                }
            if (sequence.size < 3) {
                throw InvalidMessageException(
                    "Node registration sequence should have at least three items (got " +
                        "${sequence.size})",
                )
            }
            val nodeCertificate =
                try {
                    deserializeCertificate(sequence[0])
                } catch (exc: CertificateException) {
                    throw InvalidMessageException(
                        "Node registration contains invalid node certificate",
                        exc,
                    )
                }
            val gatewayCertificate =
                try {
                    deserializeCertificate(sequence[1])
                } catch (exc: CertificateException) {
                    throw InvalidMessageException(
                        "Node registration contains invalid gateway certificate",
                        exc,
                    )
                }
            val gatewayInternetAddress = ASN1Utils.getVisibleString(sequence[2]).string
            if (!DNS.isValidDomainName(gatewayInternetAddress)) {
                throw InvalidMessageException(
                    "Malformed gateway Internet address ($gatewayInternetAddress)",
                )
            }
            val gatewaySessionKey =
                if (4 <= sequence.size) getSessionKeyFromSequence(sequence[3]) else null
            return PrivateNodeRegistration(
                nodeCertificate,
                gatewayCertificate,
                gatewayInternetAddress,
                gatewaySessionKey,
            )
        }

        private fun getSessionKeyFromSequence(sessionKeyASN1: ASN1TaggedObject): SessionKey {
            val sessionKeySequence = DERSequence.getInstance(sessionKeyASN1, false)
            if (sessionKeySequence.size() < 2) {
                throw InvalidMessageException(
                    "Session key SEQUENCE should have at least 2 items " +
                        "(got ${sessionKeySequence.size()})",
                )
            }
            val sessionKeyId =
                ASN1Utils.getOctetString(
                    sessionKeySequence.getObjectAt(0) as ASN1TaggedObject,
                ).octets

            val sessionPublicKeyASN1 =
                ASN1Utils.getOctetString(sessionKeySequence.getObjectAt(1) as ASN1TaggedObject)
            val sessionPublicKey =
                try {
                    sessionPublicKeyASN1.octets.deserializeECPublicKey()
                } catch (exc: KeyException) {
                    throw InvalidMessageException(
                        "Session key is not a valid ECDH public key",
                        exc,
                    )
                }
            return SessionKey(sessionKeyId, sessionPublicKey)
        }

        @Throws(CertificateException::class)
        private fun deserializeCertificate(asn1Object: ASN1TaggedObject): Certificate {
            val certificateASN1 = ASN1Utils.getOctetString(asn1Object)
            return Certificate.deserialize(certificateASN1.octets)
        }
    }
}
