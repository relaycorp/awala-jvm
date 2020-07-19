package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.DERVisibleString
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
            arrayOf(
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
        private val FORMAT_SIGNATURE = byteArrayOf(
            *"Relaynet".toByteArray(),
            concreteMessageType,
            concreteMessageVersion
        )

        /**
         * Deserialize PCA.
         */
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): ParcelCollectionAck {
            TODO()
        }
    }
}
