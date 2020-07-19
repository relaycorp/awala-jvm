package tech.relaycorp.relaynet.wrappers.asn1

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import java.io.IOException

internal object ASN1Utils {
    fun serializeSequence(items: Array<ASN1Encodable>, explicitTagging: Boolean = true): ByteArray {
        val messagesVector = ASN1EncodableVector(items.size)
        val finalItems = if (explicitTagging) items.asList() else items.mapIndexed { index, item ->
            DERTaggedObject(false, index, item)
        }
        finalItems.forEach { messagesVector.add(it) }
        val sequence = DERSequence(messagesVector)
        return sequence.encoded
    }

    @Throws(ASN1Exception::class)
    fun deserializeSequence(serialization: ByteArray): Array<ASN1Encodable> {
        val asn1InputStream = ASN1InputStream(serialization)
        val asn1Value = try {
            asn1InputStream.readObject()
        } catch (_: IOException) {
            throw ASN1Exception("Value is not DER-encoded")
        }
        val fieldSequence: ASN1Sequence = try {
            ASN1Sequence.getInstance(asn1Value)
        } catch (_: IllegalArgumentException) {
            throw ASN1Exception("Value is not an ASN.1 sequence")
        }
        return fieldSequence.toArray()
    }
}
