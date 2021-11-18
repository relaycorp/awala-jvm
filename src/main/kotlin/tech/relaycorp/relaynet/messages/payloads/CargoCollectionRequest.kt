package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CargoCollectionRequest(
    val cargoDeliveryAuthorization: Certificate
) : GatewayEncryptedPayload() {
    override fun serializePlaintext(): ByteArray {
        val cdaASN1 = DEROctetString(cargoDeliveryAuthorization.serialize())
        return ASN1Utils.serializeSequence(listOf(cdaASN1), false)
    }

    companion object {
        @Throws(RAMFException::class)
        fun deserialize(serialization: ByteArray): CargoCollectionRequest {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw RAMFException("CCR is not a valid DER sequence", exc)
            }

            if (sequence.isEmpty()) {
                throw RAMFException("CCR should have at least one item")
            }

            val cdaASN1 = DEROctetString.getInstance(sequence.first(), false)
            val cda = try {
                Certificate.deserialize(cdaASN1.octets)
            } catch (exc: CertificateException) {
                throw RAMFException("CDA contained in CCR is invalid", exc)
            }

            return CargoCollectionRequest(cda)
        }
    }
}
