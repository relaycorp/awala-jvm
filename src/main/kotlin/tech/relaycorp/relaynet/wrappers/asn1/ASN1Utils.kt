package tech.relaycorp.relaynet.wrappers.asn1

import java.io.IOException
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERVisibleString

internal object ASN1Utils {
    val BER_DATETIME_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

    fun makeSequence(items: List<ASN1Encodable>, explicitTagging: Boolean = true): DERSequence {
        val messagesVector = ASN1EncodableVector(items.size)
        val finalItems = if (explicitTagging) items else items.mapIndexed { index, item ->
            DERTaggedObject(false, index, item)
        }
        finalItems.forEach { messagesVector.add(it) }
        return DERSequence(messagesVector)
    }

    fun serializeSequence(items: List<ASN1Encodable>, explicitTagging: Boolean = true): ByteArray {
        return makeSequence(items, explicitTagging).encoded
    }

    @Throws(ASN1Exception::class)
    inline fun <reified T : ASN1Encodable> deserializeHomogeneousSequence(
        serialization: ByteArray
    ): Array<T> {
        if (serialization.isEmpty()) {
            throw ASN1Exception("Value is empty")
        }
        val asn1InputStream = ASN1InputStream(serialization)
        val asn1Value = try {
            asn1InputStream.readObject()
        } catch (_: IOException) {
            throw ASN1Exception("Value is not DER-encoded")
        }
        val sequence = try {
            ASN1Sequence.getInstance(asn1Value)
        } catch (_: IllegalArgumentException) {
            throw ASN1Exception("Value is not an ASN.1 sequence")
        }
        return sequence.map {
            if (it !is T) {
                throw ASN1Exception(
                    "Sequence contains an item of an unexpected type " +
                        "(${it::class.java.simpleName})"
                )
            }
            @Suppress("USELESS_CAST")
            it as T
        }.toTypedArray()
    }

    @Throws(ASN1Exception::class)
    fun deserializeHeterogeneousSequence(serialization: ByteArray): Array<ASN1TaggedObject> =
        deserializeHomogeneousSequence(serialization)

    fun derEncodeUTCDate(date: ZonedDateTime): DERGeneralizedTime {
        val dateUTC = date.withZoneSameInstant(ZoneOffset.UTC)
        return DERGeneralizedTime(dateUTC.format(BER_DATETIME_FORMATTER))
    }

    @Throws(ASN1Exception::class)
    fun getOID(oidSerialized: ASN1TaggedObject): ASN1ObjectIdentifier {
        return try {
            ASN1ObjectIdentifier.getInstance(oidSerialized, false)
        } catch (exc: IllegalArgumentException) {
            throw ASN1Exception("Value is not an OID", exc)
        }
    }

    fun getVisibleString(visibleString: ASN1TaggedObject): DERVisibleString =
        DERVisibleString.getInstance(visibleString, false)

    fun getOctetString(octetString: ASN1TaggedObject): ASN1OctetString =
        DEROctetString.getInstance(octetString, false)
}
