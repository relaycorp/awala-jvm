package tech.relaycorp.relaynet.wrappers.asn1

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import java.io.IOException

internal object ASN1Utils {
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
