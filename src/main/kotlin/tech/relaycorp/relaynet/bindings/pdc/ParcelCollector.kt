package tech.relaycorp.relaynet.bindings.pdc

import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.ramf.RecipientAddressType
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class ParcelCollector(
    val parcelSerialized: ByteArray,
    val trustedCertificates: Collection<Certificate>,
    val ack: suspend () -> Unit
) {
    @Throws(RAMFException::class, InvalidMessageException::class)
    fun deserializeAndValidateParcel(): Parcel =
        Parcel.deserialize(parcelSerialized)
            .also { it.validate(RecipientAddressType.PRIVATE, trustedCertificates) }
}
