package tech.relaycorp.relaynet.messages.control

import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZoneId
import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.RSASigning
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Private Node Registration Authorization (PNRA).
 */
class PrivateNodeRegistrationAuthorization(
    val expiryDate: ZonedDateTime,
    val gatewayData: ByteArray
) {
    /**
     * Sign and serialize.
     */
    fun serialize(gatewayPrivateKey: PrivateKey): ByteArray {
        val expiryDateASN1 = ASN1Utils.derEncodeUTCDate(expiryDate)
        val gatewayDataASN1 = DEROctetString(gatewayData)
        val signaturePlaintext = makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1)
        val signature = RSASigning.sign(signaturePlaintext, gatewayPrivateKey)
        return ASN1Utils.serializeSequence(
            arrayOf(expiryDateASN1, gatewayDataASN1, DEROctetString(signature)),
            false
        )
    }

    companion object {
        /**
         * Deserialize and validate.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(
            serialization: ByteArray,
            gatewayPublicKey: PublicKey
        ): PrivateNodeRegistrationAuthorization {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("PNRA is not a valid DER sequence", exc)
            }

            if (sequence.size < 3) {
                throw InvalidMessageException(
                    "PNRA plaintext should have at least 3 items (got ${sequence.size})"
                )
            }

            val expiryDateASN1 = DERGeneralizedTime.getInstance(sequence[0], false)
            val expiryDate =
                ZonedDateTime.ofInstant(expiryDateASN1.date.toInstant(), ZoneId.systemDefault())
            if (expiryDate < ZonedDateTime.now()) {
                throw InvalidMessageException("PNRA already expired")
            }

            val gatewayDataASN1 = ASN1Utils.getOctetString(sequence[1])

            val signature = ASN1Utils.getOctetString(sequence[2]).octets
            val expectedPlaintext = makeSignaturePlaintext(expiryDateASN1, gatewayDataASN1)
            if (!RSASigning.verify(signature, gatewayPublicKey, expectedPlaintext)) {
                throw InvalidMessageException("PNRA signature is invalid")
            }

            return PrivateNodeRegistrationAuthorization(expiryDate, gatewayDataASN1.octets)
        }

        private fun makeSignaturePlaintext(
            expiryDateASN1: ASN1GeneralizedTime,
            gatewayDataASN1: ASN1OctetString
        ) = ASN1Utils.serializeSequence(arrayOf(OIDs.PNRA, expiryDateASN1, gatewayDataASN1), false)
    }
}
