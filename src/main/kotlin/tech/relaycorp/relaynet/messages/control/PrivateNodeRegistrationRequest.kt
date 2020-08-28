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
 * Private Node Registration Request (PNRR).
 *
 * @param privateNodePublicKey The private node's public key
 * @param pnraSerialized The [PrivateNodeRegistrationAuthorization] serialized
 */
class PrivateNodeRegistrationRequest(
    val privateNodePublicKey: PublicKey,
    val pnraSerialized: ByteArray
) {
    /**
     * Sign and serialize.
     */
    fun serialize(privateNodePrivateKey: PrivateKey): ByteArray {
        val pnraSerializedASN1 = DEROctetString(pnraSerialized)
        val pnraCountersignaturePlaintext = makePNRACountersignaturePlaintext(pnraSerializedASN1)
        val pnraCountersignature =
            RSASigning.sign(pnraCountersignaturePlaintext, privateNodePrivateKey)
        return ASN1Utils.serializeSequence(
            arrayOf(
                DEROctetString(privateNodePublicKey.encoded),
                pnraSerializedASN1,
                DEROctetString(pnraCountersignature)
            ),
            false
        )
    }

    companion object {
        /**
         * Deserialize and validate PNRR.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): PrivateNodeRegistrationRequest {
            val pnrrSequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("PNRR is not a DER sequence", exc)
            }
            if (pnrrSequence.size < 3) {
                throw InvalidMessageException(
                    "PNRR sequence should have at least 3 items (got ${pnrrSequence.size})"
                )
            }
            val privateNodePublicKeyASN1 = ASN1Utils.getOctetString(pnrrSequence[0])
            val privateNodePublicKey = try {
                privateNodePublicKeyASN1.octets.deserializeRSAPublicKey()
            } catch (exc: KeyException) {
                throw InvalidMessageException("Private node public key is invalid", exc)
            }

            val pnraSerialized = ASN1Utils.getOctetString(pnrrSequence[1])
            val pnraCounterSignature = ASN1Utils.getOctetString(pnrrSequence[2]).octets
            verifyPNRACountersignature(pnraSerialized, pnraCounterSignature, privateNodePublicKey)

            return PrivateNodeRegistrationRequest(privateNodePublicKey, pnraSerialized.octets)
        }

        @Throws(InvalidMessageException::class)
        private fun verifyPNRACountersignature(
            pnraSerialized: ASN1OctetString,
            pnraCountersignature: ByteArray,
            privateNodePublicKey: PublicKey
        ) {
            val expectedPlaintext = makePNRACountersignaturePlaintext(pnraSerialized)
            if (!RSASigning.verify(pnraCountersignature, privateNodePublicKey, expectedPlaintext)) {
                throw InvalidMessageException("PNRA countersignature is invalid")
            }
        }

        private fun makePNRACountersignaturePlaintext(
            pnraSerializedASN1: ASN1OctetString
        ): ByteArray = ASN1Utils.serializeSequence(
            arrayOf(OIDs.PNRA_COUNTERSIGNATURE, pnraSerializedASN1),
            false
        )
    }
}
