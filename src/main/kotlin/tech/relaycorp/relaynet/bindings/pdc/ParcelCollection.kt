package tech.relaycorp.relaynet.bindings.pdc

import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RecipientAddressType
import tech.relaycorp.relaynet.wrappers.x509.Certificate

/**
 * Collection of a single parcel.
 *
 * @param parcelSerialized The serialization of the parcel
 * @param trustedCertificates The collection of certificates regarded trusted
 * @param ack The callback to execute when the collection is acknowledged
 */
class ParcelCollection(
    val parcelSerialized: ByteArray,
    val trustedCertificates: Collection<Certificate>,
    val ack: suspend () -> Unit
) {
    /**
     * Deserialize and validate the parcel being collected.
     *
     * The parcel will be refused if it's bound for a public endpoint or if the sender is not
     * authorized to reach the recipient.
     */
    @Throws(RAMFException::class, InvalidMessageException::class)
    fun deserializeAndValidateParcel(): Parcel =
        Parcel.deserialize(parcelSerialized)
            .also { it.validate(RecipientAddressType.PRIVATE, trustedCertificates) }
}
