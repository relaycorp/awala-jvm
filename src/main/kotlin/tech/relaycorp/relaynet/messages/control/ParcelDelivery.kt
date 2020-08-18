package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Parcel delivery.
 */
public class ParcelDelivery(public val deliveryId: String, public val parcelSerialized: ByteArray) {
    /**
     * Serialize delivery.
     */
    public fun serialize(): ByteArray = ASN1Utils.serializeSequence(
        arrayOf(DERVisibleString(deliveryId), DEROctetString(parcelSerialized)),
        false
    )

    public companion object {
        /**
         * Deserialize delivery
         */
        @Throws(InvalidMessageException::class)
        public fun deserialize(serialization: ByteArray): ParcelDelivery {
            val sequence = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Delivery is not a DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw InvalidMessageException(
                    "Delivery sequence should have at least 2 items (got ${sequence.size})"
                )
            }
            val deliveryIdASN1 =
                DERVisibleString.getInstance(sequence[0] as ASN1TaggedObject, false)
            val parcelSerializedASN1 =
                DEROctetString.getInstance(sequence[1] as ASN1TaggedObject, false)
            return ParcelDelivery(deliveryIdASN1.string, parcelSerializedASN1.octets)
        }
    }
}
