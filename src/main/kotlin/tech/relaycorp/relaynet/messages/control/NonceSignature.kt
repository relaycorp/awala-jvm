package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey

/**
 * Nonce signature.
 */
class NonceSignature(val nonce: ByteArray, val signerCertificate: Certificate) {
    /**
     * Serialize signature.
     */
    fun serialize(privateKey: PrivateKey): ByteArray {
        val plaintext = ASN1Utils.serializeSequence(
            arrayOf(OIDs.NONCE_SIGNATURE, DEROctetString(nonce)),
            false
        )
        val signedData = SignedData.sign(
            plaintext,
            privateKey,
            signerCertificate,
            encapsulatedCertificates = setOf(signerCertificate)
        )
        return signedData.serialize()
    }

    companion object {
        /**
         * Deserialize and validate nonce signature.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): NonceSignature {
            val signedData = try {
                SignedData.deserialize(serialization).also { it.verify() }
            } catch (exc: SignedDataException) {
                throw InvalidMessageException("SignedData value is invalid", exc)
            }
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(signedData.plaintext!!)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Signature plaintext is not a DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw InvalidMessageException(
                    "Signature sequence should have at least 2 items (got ${sequence.size})"
                )
            }
            val oid = ASN1Utils.getOID(sequence.first())
            if (oid != OIDs.NONCE_SIGNATURE) {
                throw InvalidMessageException("Signature OID is invalid (got ${oid.id})")
            }
            val nonce = ASN1Utils.getOctetString(sequence[1])
            return NonceSignature(nonce.octets, signedData.signerCertificate!!)
        }
    }
}
