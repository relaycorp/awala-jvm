package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.RSASigning
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZoneId
import java.time.ZonedDateTime

/**
 * Client Registration Authorization.
 */
class ClientRegistrationAuthorization(val expiryDate: ZonedDateTime, val serverData: ByteArray) {
    /**
     * Sign and serialize CRA
     */
    fun serialize(serverPrivateKey: PrivateKey): ByteArray {
        val expiryDateASN1 = ASN1Utils.derEncodeUTCDate(expiryDate)
        val serverDataASN1 = DEROctetString(serverData)
        val signaturePlaintext = makeSignaturePlaintext(expiryDateASN1, serverDataASN1)
        val signature = RSASigning.sign(signaturePlaintext, serverPrivateKey)
        return ASN1Utils.serializeSequence(
            arrayOf(expiryDateASN1, serverDataASN1, DEROctetString(signature)),
            false
        )
    }

    companion object {
        /**
         * Deserialize and validate CRA.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(
            serialization: ByteArray,
            serverPublicKey: PublicKey
        ): ClientRegistrationAuthorization {
            val sequence = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("CRA is not a valid DER sequence", exc)
            }

            if (sequence.size < 3) {
                throw InvalidMessageException(
                    "CRA plaintext should have at least 3 items (got ${sequence.size})"
                )
            }

            val expiryDateASN1 = DERGeneralizedTime.getInstance(sequence[0], false)
            val expiryDate =
                ZonedDateTime.ofInstant(expiryDateASN1.date.toInstant(), ZoneId.systemDefault())
            if (expiryDate < ZonedDateTime.now()) {
                throw InvalidMessageException("CRA already expired")
            }

            val serverDataASN1 = ASN1Utils.getOctetString(sequence[1])

            val signature = ASN1Utils.getOctetString(sequence[2]).octets
            val expectedPlaintext = makeSignaturePlaintext(expiryDateASN1, serverDataASN1)
            if (!RSASigning.verify(signature, serverPublicKey, expectedPlaintext)) {
                throw InvalidMessageException("CRA signature is invalid")
            }

            return ClientRegistrationAuthorization(expiryDate, serverDataASN1.octets)
        }

        private fun makeSignaturePlaintext(
            expiryDateASN1: ASN1GeneralizedTime,
            serverDataASN1: ASN1OctetString
        ) = ASN1Utils.serializeSequence(arrayOf(OIDs.CRA, expiryDateASN1, serverDataASN1), false)
    }
}
