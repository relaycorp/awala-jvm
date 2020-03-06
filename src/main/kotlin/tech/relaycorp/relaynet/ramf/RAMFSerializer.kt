package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.string.BerVisibleString
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.time.ZoneId

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
        reverseOS.flush()
        return reverseOS.array
    }

    @Throws(RAMFException::class)
    fun deserialize(serialization: ByteArray): RAMFMessage {
        val formatSignatureLength = 10
        if (serialization.size < formatSignatureLength) {
            throw RAMFException("Serialization is too short to contain format signature")
        }
        val magicConstant = serialization.sliceArray(0..8).toString()
        if (magicConstant != "Relaynet") {
            throw RAMFException("Format signature should start with magic constant 'Relaynet'")
        }
        throw Error("Unimplemented")
    }

//    @Throws(IOException::class)
//    fun decode(_is: InputStream): Int {
//        var codeLength = 0
//        var subCodeLength = 0
//        val berTag = BerTag()
//        codeLength += tag.decodeAndCheck(_is)
//        val length = BerLength()
//        codeLength += length.decode(_is)
//        val totalLength = length.`val`
//        codeLength += totalLength
//        subCodeLength += berTag.decode(_is)
//        if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 0)) {
//            val recipientBer = BerVisibleString()
//            subCodeLength += recipientBer.decode(_is, false)
//            subCodeLength += berTag.decode(_is)
//        } else {
//            throw IOException("Tag does not match the mandatory sequence element tag.")
//        }
//        if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 1)) {
//            val messageIdBer = BerVisibleString()
//            subCodeLength += messageIdBer.decode(_is, false)
//            subCodeLength += berTag.decode(_is)
//        } else {
//            throw IOException("Tag does not match the mandatory sequence element tag.")
//        }
//        if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 2)) {
//            val creationTimeUtcBer = BerDateTime()
//            subCodeLength += creationTimeUtcBer.decode(_is, false)
//            subCodeLength += berTag.decode(_is)
//        } else {
//            throw IOException("Tag does not match the mandatory sequence element tag.")
//        }
//        if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 3)) {
//            val ttlBer = BerInteger()
//            subCodeLength += ttlBer.decode(_is, false)
//            subCodeLength += berTag.decode(_is)
//        } else {
//            throw IOException("Tag does not match the mandatory sequence element tag.")
//        }
//        if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 4)) {
//            val payloadBer = BerOctetString()
//            subCodeLength += payloadBer.decode(_is, false)
//            if (subCodeLength == totalLength) {
//                // TODO: Initialise class and return instance instead
//                return codeLength
//            }
//        }
//        throw IOException("Unexpected end of sequence, length tag: $totalLength, actual sequence length: $subCodeLength")
//    }
}
