package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.string.BerVisibleString
import java.io.IOException
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

val berDateTimeFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

internal class RAMFSerializer(
    val recipient: String,
    val messageId: String,
    val creationTimeUtc: LocalDateTime,
    val ttl: Int,
    val payload: ByteArray
) {

    @Throws(IOException::class)
    fun encode(): ByteArray {
        val reverseOS = ReverseByteArrayOutputStream(1000)
        var codeLength = 0

        codeLength += BerOctetString(payload).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 4
        reverseOS.write(0x84)
        codeLength += 1

        codeLength += BerInteger(ttl.toBigInteger()).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 3
        reverseOS.write(0x83)
        codeLength += 1

        codeLength += BerDateTime(creationTimeUtc.format(berDateTimeFormatter)).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 2
        reverseOS.write(0x82)
        codeLength += 1

        codeLength += BerVisibleString(messageId).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 1
        reverseOS.write(0x81)
        codeLength += 1

        codeLength += BerVisibleString(recipient).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 0
        reverseOS.write(0x80)
        codeLength += 1

        BerLength.encodeLength(reverseOS, codeLength)
        tag.encode(reverseOS)
        return reverseOS.array
    }

    @Throws(IOException::class)
    fun decode(): Int {
//    fun decode(_is: InputStream): Int {
        throw NotImplementedError(
            "See https://github.com/relaycorp/relaynet-jvm/issues/9"
        )
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
    }

    companion object {
        val tag = BerTag(BerTag.UNIVERSAL_CLASS, BerTag.CONSTRUCTED, 16)
    }
}
