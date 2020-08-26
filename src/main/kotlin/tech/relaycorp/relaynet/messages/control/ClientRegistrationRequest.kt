package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.RSASigning
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.deserializeRSAPublicKey
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Client Registration Request.
 *
 * @param clientPublicKey The client's public key
 * @param craSerialized The [ClientRegistrationAuthorization] serialized
 */
class ClientRegistrationRequest(
    val clientPublicKey: PublicKey,
    val craSerialized: ByteArray
) {
    /**
     * Sign and serialize CRR.
     */
    fun serialize(clientPrivateKey: PrivateKey): ByteArray {
        val craCountersignaturePlaintext = ASN1Utils.serializeSequence(
            arrayOf(OIDs.CRA_COUNTERSIGNATURE, DEROctetString(craSerialized)),
            false
        )
        val craCountersignature = RSASigning.sign(craCountersignaturePlaintext, clientPrivateKey)
        return ASN1Utils.serializeSequence(
            arrayOf(
                DEROctetString(clientPublicKey.encoded),
                DEROctetString(craSerialized),
                DEROctetString(craCountersignature)
            ),
            false
        )
    }

    companion object {
        /**
         * Deserialize and validate CRR.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): ClientRegistrationRequest {
            val crrSequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("CRR is not a DER sequence", exc)
            }
            if (crrSequence.size < 3) {
                throw InvalidMessageException(
                    "CRR sequence should have at least 3 items (got ${crrSequence.size})"
                )
            }
            val clientPublicKeyASN1 = ASN1Utils.getOctetString(crrSequence[0])
            val clientPublicKey = try {
                clientPublicKeyASN1.octets.deserializeRSAPublicKey()
            } catch (exc: KeyException) {
                throw InvalidMessageException("Client public key is invalid", exc)
            }

            val craSerialized = ASN1Utils.getOctetString(crrSequence[1])
            val craCounterSignature = ASN1Utils.getOctetString(crrSequence[2]).octets
            verifyCRACountersignature(craSerialized, craCounterSignature, clientPublicKey)

            return ClientRegistrationRequest(clientPublicKey, craSerialized.octets)
        }

        @Throws(InvalidMessageException::class)
        private fun verifyCRACountersignature(
            craSerialized: ASN1OctetString,
            craCountersignature: ByteArray,
            clientPublicKey: PublicKey
        ) {
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(OIDs.CRA_COUNTERSIGNATURE, craSerialized),
                false
            )
            if (!RSASigning.verify(craCountersignature, clientPublicKey, expectedPlaintext)) {
                throw InvalidMessageException("CRA countersignature is invalid")
            }
        }
    }
}
