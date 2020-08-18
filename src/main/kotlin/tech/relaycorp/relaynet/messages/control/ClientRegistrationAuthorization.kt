package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
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
public class ClientRegistrationAuthorization(
    public val expiryDate: ZonedDateTime,
    public val serverData: ByteArray
) {
    /**
     * Sign and serialize CRA
     */
    public fun serialize(serverPrivateKey: PrivateKey): ByteArray {
        val plaintext = ASN1Utils.serializeSequence(
            arrayOf(
                OIDs.CRA,
                ASN1Utils.derEncodeUTCDate(expiryDate),
                DEROctetString(serverData)
            ),
            false
        )
        val signedData = SignedData.sign(plaintext, serverPrivateKey)
        return signedData.serialize()
    }

    public companion object {
        /**
         * Deserialize and validate CRA.
         */
        @Throws(InvalidMessageException::class)
        public fun deserialize(
            serialization: ByteArray,
            serverPublicKey: PublicKey
        ): ClientRegistrationAuthorization {
            val signedData = try {
                SignedData.deserialize(serialization)
                    .also { it.verify(signerPublicKey = serverPublicKey) }
            } catch (exc: SignedDataException) {
                throw InvalidMessageException("Serialization is not a valid SignedData value", exc)
            }
            val sequence = try {
                ASN1Utils.deserializeSequence(signedData.plaintext!!)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("CRA plaintext should be a DER sequence")
            }

            if (sequence.size < 3) {
                throw InvalidMessageException(
                    "CRA plaintext should have at least 3 items (got ${sequence.size})"
                )
            }

            val oid = ASN1ObjectIdentifier.getInstance(sequence.first() as ASN1TaggedObject, false)
            if (oid != OIDs.CRA) {
                throw InvalidMessageException(
                    "CRA plaintext has invalid OID (got ${oid.id})"
                )
            }

            val expiryDateDer =
                DERGeneralizedTime.getInstance(sequence[1] as ASN1TaggedObject, false)
            val expiryDate =
                ZonedDateTime.ofInstant(expiryDateDer.date.toInstant(), ZoneId.systemDefault())
            if (expiryDate < ZonedDateTime.now()) {
                throw InvalidMessageException("CRA already expired")
            }

            val serverDataDER = DEROctetString.getInstance(sequence[2] as ASN1TaggedObject, false)

            return ClientRegistrationAuthorization(expiryDate, serverDataDER.octets)
        }
    }
}
