package tech.relaycorp.relaynet.wrappers.asn1

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
import java.io.IOException
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

internal object ASN1Utils {
    val BER_DATETIME_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

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
    fun deserializeSequence(serialization: ByteArray): Array<ASN1TaggedObject> {
        if (serialization.isEmpty()) {
            throw ASN1Exception("Value is empty")
        }
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
        val implicitlyTaggedItems = fieldSequence.map {
            if (it !is ASN1TaggedObject) {
                throw ASN1Exception("Sequence contains explicitly tagged item")
            }
            it as ASN1TaggedObject
        }
        return implicitlyTaggedItems.toTypedArray()
    }

    fun derEncodeUTCDate(date: ZonedDateTime): DERGeneralizedTime {
        val dateUTC = date.withZoneSameInstant(ZoneOffset.UTC)
        return DERGeneralizedTime(dateUTC.format(BER_DATETIME_FORMATTER))
    }

    @Throws(ASN1Exception::class)
    fun getOID(
        oidSerialized: ASN1TaggedObject,
        explicitTagging: Boolean = false
    ): ASN1ObjectIdentifier {
        return try {
            ASN1ObjectIdentifier.getInstance(oidSerialized, explicitTagging)
        } catch (exc: IllegalArgumentException) {
            throw ASN1Exception("Value is not an OID", exc)
        }
    }

    @Throws(ASN1Exception::class)
    fun getOID(oidSerialized: ASN1Encodable) =
        getOID(oidSerialized as ASN1TaggedObject, false)

    fun getVisibleString(visibleString: ASN1TaggedObject): DERVisibleString =
        DERVisibleString.getInstance(visibleString, false)

    fun getOctetString(octetString: ASN1TaggedObject): ASN1OctetString =
        DEROctetString.getInstance(octetString, false)
}
