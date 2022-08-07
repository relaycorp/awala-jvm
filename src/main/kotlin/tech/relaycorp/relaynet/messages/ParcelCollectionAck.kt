package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Parcel Collection Acknowledgement (PCA).
 */
class ParcelCollectionAck(
    val senderEndpointPrivateAddress: String,
    val recipientEndpointAddress: String,
    val parcelId: String
) {
    /**
     * Serialize PCA.
     */
    fun serialize(): ByteArray {
        val sequence = ASN1Utils.serializeSequence(
            listOf(
                DERVisibleString(senderEndpointPrivateAddress),
                DERVisibleString(recipientEndpointAddress),
                DERVisibleString(parcelId)
            ),
            false
        )
        return FORMAT_SIGNATURE + sequence
    }

    companion object {
        private const val concreteMessageType: Byte = 0x51
        private const val concreteMessageVersion: Byte = 0
        internal val FORMAT_SIGNATURE = byteArrayOf(
            *"Awala".toByteArray(),
            concreteMessageType,
            concreteMessageVersion
        )

        /**
         * Deserialize PCA.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): ParcelCollectionAck {
            if (serialization.size < 7) {
                throw InvalidMessageException("Message is too short to contain format signature")
            }
            val formatSignature = serialization.slice(FORMAT_SIGNATURE.indices)
            if (formatSignature != FORMAT_SIGNATURE.asList()) {
                throw InvalidMessageException("Format signature is not that of a PCA")
            }
            val derSequence =
                serialization.sliceArray(FORMAT_SIGNATURE.size until serialization.size)
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(derSequence)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("PCA is not a valid DER sequence", exc)
            }
            if (sequence.size < 3) {
                throw InvalidMessageException("PCA should have 3 items (got ${sequence.size})")
            }
            val fields = sequence.map { ASN1Utils.getVisibleString(it) }
            return ParcelCollectionAck(fields[0].string, fields[1].string, fields[2].string)
        }
    }
}
