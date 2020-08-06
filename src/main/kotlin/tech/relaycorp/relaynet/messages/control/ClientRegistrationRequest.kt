package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
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
        val craCountersignature = SignedData.sign(craCountersignaturePlaintext, clientPrivateKey)
        return ASN1Utils.serializeSequence(
            arrayOf(
                DEROctetString(clientPublicKey.encoded),
                DEROctetString(craCountersignature.serialize())
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
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("CRR is not a DER sequence", exc)
            }
            if (crrSequence.size < 2) {
                throw InvalidMessageException(
                    "CRR sequence should have at least 2 items (got ${crrSequence.size})"
                )
            }
            val clientPublicKeyASN1 =
                DEROctetString.getInstance(crrSequence[0] as ASN1TaggedObject, false)
            val clientPublicKey = try {
                clientPublicKeyASN1.octets.deserializeRSAPublicKey()
            } catch (exc: KeyException) {
                throw InvalidMessageException("Client public key is invalid", exc)
            }

            val craSerialized =
                extractCRAFromCountersignature(crrSequence[1] as ASN1TaggedObject, clientPublicKey)

            return ClientRegistrationRequest(clientPublicKey, craSerialized)
        }

        @Throws(InvalidMessageException::class)
        private fun extractCRAFromCountersignature(
            craCountersignatureASN1: ASN1TaggedObject,
            clientPublicKey: PublicKey
        ): ByteArray {
            val craCountersignatureSerialized =
                DEROctetString.getInstance(craCountersignatureASN1, false).octets
            val craCountersignature = try {
                SignedData.deserialize(craCountersignatureSerialized)
                    .also { it.verify(signerPublicKey = clientPublicKey) }
            } catch (exc: SignedDataException) {
                throw InvalidMessageException(
                    "CRA countersignature is not a valid SignedData value",
                    exc
                )
            }
            val craCountersignatureSequence = try {
                ASN1Utils.deserializeSequence(craCountersignature.plaintext!!)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException(
                    "CRA countersignature plaintext should be a DER sequence",
                    exc
                )
            }
            if (craCountersignatureSequence.size < 2) {
                throw InvalidMessageException(
                    "CRA countersignature sequence should have at least 2 items (got " +
                        "${craCountersignatureSequence.size})"
                )
            }
            val craCountersignatureOID = ASN1ObjectIdentifier.getInstance(
                craCountersignatureSequence[0] as ASN1TaggedObject, false
            )
            if (craCountersignatureOID != OIDs.CRA_COUNTERSIGNATURE) {
                throw InvalidMessageException(
                    "CRA countersignature has invalid OID (got ${craCountersignatureOID.id})"
                )
            }

            val craSerializationASN1 = craCountersignatureSequence[1] as ASN1TaggedObject
            return DEROctetString.getInstance(craSerializationASN1, false).octets
        }
    }
}
