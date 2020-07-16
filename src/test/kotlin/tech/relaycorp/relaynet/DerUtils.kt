package tech.relaycorp.relaynet

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERSequence

fun parseDer(derSerialization: ByteArray): ASN1Primitive {
    val asn1Stream = ASN1InputStream(derSerialization)
    return asn1Stream.readObject()
}

fun serializeSequence(vararg elements: ASN1Encodable): ByteArray {
    val vector = ASN1EncodableVector(elements.size)
    elements.forEach { vector.add(it) }
    val sequence = DERSequence(elements)
    return sequence.encoded
}
