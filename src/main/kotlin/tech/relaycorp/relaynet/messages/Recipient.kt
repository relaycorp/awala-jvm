package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.DNS
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

data class Recipient(val id: String, val internetAddress: String? = null) {
    internal fun serialize(): ASN1Sequence {
        val idEncoded = DERVisibleString(id)
        val additionalFields =
            if (internetAddress != null) {
                listOf(DERVisibleString(internetAddress))
            } else {
                listOf()
            }
        return ASN1Utils.makeSequence(listOf(idEncoded) + additionalFields, false)
    }

    companion object {
        private const val ADDRESS_MAX_LENGTH = 1024
        private val idRegex = "^0[a-f0-9]+$".toRegex()

        @Throws(RAMFException::class)
        internal fun deserialize(sequence: ASN1Sequence): Recipient {
            if (sequence.size() == 0) {
                throw RAMFException("Recipient SEQUENCE is empty")
            }
            val id = deserializeId(sequence.first())
            val internetAddress =
                if (1 < sequence.size()) {
                    deserializeInternetAddress(sequence.getObjectAt(1))
                } else {
                    null
                }
            return Recipient(id, internetAddress)
        }

        @Throws(RAMFException::class)
        internal fun deserialize(serialization: ASN1TaggedObject): Recipient {
            val sequence =
                try {
                    DERSequence.getInstance(serialization, false)
                } catch (exc: IllegalStateException) {
                    throw RAMFException("Recipient is not an implicitly-tagged SEQUENCE", exc)
                }
            return deserialize(sequence)
        }

        @Throws(RAMFException::class)
        private fun deserializeId(idRaw: ASN1Encodable): String {
            val idEncoded = ASN1TaggedObject.getInstance(idRaw)
            val idString = ASN1Utils.getVisibleString(idEncoded)
            val id = idString.string
            val length = id.length
            if (ADDRESS_MAX_LENGTH < length) {
                throw RAMFException(
                    "Recipient id should not span more than $ADDRESS_MAX_LENGTH characters " +
                        "(got $length)",
                )
            }
            if (!idRegex.matches(id)) {
                throw RAMFException("Recipient id is malformed ($id)")
            }
            return id
        }

        @Throws(RAMFException::class)
        private fun deserializeInternetAddress(internetAddressRaw: ASN1Encodable): String {
            val addressEncoded = ASN1TaggedObject.getInstance(internetAddressRaw)
            val addressString = ASN1Utils.getVisibleString(addressEncoded)
            val address = addressString.string
            val length = address.length
            if (ADDRESS_MAX_LENGTH < length) {
                throw RAMFException(
                    "Internet address should not span more than $ADDRESS_MAX_LENGTH characters " +
                        "(got $length)",
                )
            }
            if (!DNS.isValidDomainName(address)) {
                throw RAMFException("Internet address is malformed ($address)")
            }
            return address
        }
    }
}
