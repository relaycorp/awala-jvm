package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Cargo message set.
 */
class CargoMessageSet(val messages: Array<ByteArray>) : PayloadPlaintext {
    /**
     * Serialize cargo message set.
     */
    override fun serialize(): ByteArray {
        val messagesVector = ASN1EncodableVector(messages.size)
        messages.forEach { messagesVector.add(DEROctetString(it)) }
        val sequence = DERSequence(messagesVector)
        return sequence.encoded
    }

    companion object {
        /**
         * Deserialize a cargo message set.
         */
        fun deserialize(serialization: ByteArray): CargoMessageSet {
            val items = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw RAMFException("Invalid CargoMessageSet", exc)
            }
            items.forEach {
                if (it !is DEROctetString) {
                    throw RAMFException("At least one message is not an OCTET STRING")
                }
            }
            val messages = items.map { (it as DEROctetString).octets }
            return CargoMessageSet(messages.toTypedArray())
        }
    }
}
