package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.string.BerVisibleString
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.Charset
import java.time.ZoneId
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERVisibleString

private val ramfMessageTag = BerTag(BerTag.UNIVERSAL_CLASS, BerTag.CONSTRUCTED, 16)

internal open class RAMFSerializer(
    val concreteMessageType: Byte,
    val concreteMessageVersion: Byte
) {
    fun serialize(fieldSet: RAMFFieldSet): ByteArray {
        val output = ByteArrayOutputStream()

        output.write("Relaynet".toByteArray())
        output.write(concreteMessageType.toInt())
        output.write(concreteMessageVersion.toInt())
        output.write(serializeFields(fieldSet))

        return output.toByteArray()
    }

    @Throws(IOException::class)
    private fun serializeFields(fieldSet: RAMFFieldSet): ByteArray {
        val reverseOS = ReverseByteArrayOutputStream(1000, true)
        var codeLength = 0

        codeLength += BerOctetString(fieldSet.payload).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 4
        reverseOS.write(0x84)
        codeLength += 1

        codeLength += BerInteger(fieldSet.ttl.toBigInteger()).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 3
        reverseOS.write(0x83)
        codeLength += 1

        val creationTimeUtc = fieldSet.creationTime.withZoneSameInstant(ZoneId.of("UTC"))
        codeLength += BerDateTime(creationTimeUtc.format(berDateTimeFormatter)).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 2
        reverseOS.write(0x82)
        codeLength += 1

        codeLength += BerVisibleString(fieldSet.messageId).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 1
        reverseOS.write(0x81)
        codeLength += 1

        codeLength += BerVisibleString(fieldSet.recipientAddress).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 0
        reverseOS.write(0x80)
        codeLength += 1

        BerLength.encodeLength(reverseOS, codeLength)
        ramfMessageTag.encode(reverseOS)
        return reverseOS.array
    }

    @Throws(RAMFException::class)
    fun deserialize(serialization: ByteArray): RAMFMessage {
        val serializationStream = ByteArrayInputStream(serialization)
        if (serializationStream.available() < 10) {
            throw RAMFException("Serialization is too short to contain format signature")
        }

        val magicConstant = serializationStream.readNBytes(8).toString(Charset.forName("ASCII"))
        if (magicConstant != "Relaynet") {
            throw RAMFException("Format signature should start with magic constant 'Relaynet'")
        }

        val messageType = serializationStream.read()
        if (messageType != concreteMessageType.toInt()) {
            throw RAMFException(
                "Message type should be $concreteMessageType (got $messageType)"
            )
        }

        val messageVersion = serializationStream.read()
        if (messageVersion != concreteMessageVersion.toInt()) {
            throw RAMFException(
                "Message version should be $concreteMessageVersion (got $messageVersion)"
            )
        }
        deserializeFields(serializationStream)
        throw Error("Unimplemented")
    }

    @Throws(RAMFException::class)
    private fun deserializeFields(serialization: InputStream) {
        val asn1InputStream = ASN1InputStream(serialization)
        val fieldSequence: ASN1Sequence = try {
            val asn1Value = asn1InputStream.readObject()
            ASN1Sequence.getInstance(asn1Value)
        } catch (exception: Exception) {
            when (exception) {
                is IOException, is IllegalArgumentException -> throw RAMFException(
                    "Message fields are not a DER-encoded sequence"
                )
                else -> throw exception
            }
        }
        val fieldSequenceSize = fieldSequence.size()
        if (fieldSequenceSize != 5) {
            throw RAMFException(
                "Field sequence should contain 5 items (got $fieldSequenceSize)"
            )
        }

        val recipientAddressRaw = fieldSequence.getObjectAt(0)
        try {
            DERVisibleString.getInstance(recipientAddressRaw)
        } catch (_: java.lang.IllegalArgumentException) {
            throw RAMFException("Recipient address should be a VisibleString")
        }
    }

    // @Throws(RAMFException::class)
    // private fun deserializeFields(serialization: InputStream): Int {
    //     var codeLength = 0
    //     var subCodeLength = 0
    //     val berTag = BerTag()
    //     try {
    //         codeLength += ramfMessageTag.decodeAndCheck(serialization)
    //     } catch (error: IOException) {
    //         throw RAMFException("Message fields are not a DER-encoded sequence")
    //     }
    //     val length = BerLength()
    //     codeLength += length.decode(serialization)
    //     val totalLength = length.`val`
    //     codeLength += totalLength
    //     subCodeLength += berTag.decode(serialization)
    //     if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 0)) {
    //         val recipientBer = BerVisibleString()
    //         subCodeLength += recipientBer.decode(serialization, false)
    //         subCodeLength += berTag.decode(serialization)
    //     } else {
    //         throw IOException("Tag does not match the mandatory sequence element tag.")
    //     }
    //     if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 1)) {
    //         val messageIdBer = BerVisibleString()
    //         subCodeLength += messageIdBer.decode(serialization, false)
    //         subCodeLength += berTag.decode(serialization)
    //     } else {
    //         throw IOException("Tag does not match the mandatory sequence element tag.")
    //     }
    //     if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 2)) {
    //         val creationTimeUtcBer = BerDateTime()
    //         subCodeLength += creationTimeUtcBer.decode(serialization, false)
    //         subCodeLength += berTag.decode(serialization)
    //     } else {
    //         throw IOException("Tag does not match the mandatory sequence element tag.")
    //     }
    //     if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 3)) {
    //         val ttlBer = BerInteger()
    //         subCodeLength += ttlBer.decode(serialization, false)
    //         subCodeLength += berTag.decode(serialization)
    //     } else {
    //         throw IOException("Tag does not match the mandatory sequence element tag.")
    //     }
    //     if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 4)) {
    //         val payloadBer = BerOctetString()
    //         subCodeLength += payloadBer.decode(serialization, false)
    //         if (subCodeLength == totalLength) {
    //             // TODO: Initialise class and return instance instead
    //             return codeLength
    //         }
    //     }
    //     throw RAMFException("Field set sequence contains more than 5 items")
    // }
}
