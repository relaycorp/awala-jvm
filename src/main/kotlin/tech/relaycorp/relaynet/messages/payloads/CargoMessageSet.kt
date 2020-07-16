package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject

/**
 * Cargo message set.
 */
class CargoMessageSet(val messages: Array<ByteArray>) : PayloadPlaintext {
    /**
     * Serialize cargo message set.
     */
    override fun serialize(): ByteArray {
        val messagesVector = ASN1EncodableVector(messages.size)
        messages.forEachIndexed { index, bytes ->
            messagesVector.add(DERTaggedObject(index, DEROctetString(bytes)))
        }
        val sequence = DERSequence(messagesVector)
        return sequence.encoded
    }
}
