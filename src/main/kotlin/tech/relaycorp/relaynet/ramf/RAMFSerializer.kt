package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.string.BerVisibleString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.wrappers.cms.SignedDataException
import tech.relaycorp.relaynet.wrappers.cms.sign
import tech.relaycorp.relaynet.wrappers.cms.verifySignature
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.Charset
import java.security.PrivateKey
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

private const val OCTETS_IN_9_MIB = 9437184

private val DER_SEQUENCE_TAG = BerTag(BerTag.UNIVERSAL_CLASS, BerTag.CONSTRUCTED, 16)
private val BER_DATETIME_FORMATTER: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyyMMddHHmmss")

private val UTC_ZONE_ID: ZoneId = ZoneId.of("UTC")

@Suppress("ArrayInDataClass")
private data class FieldSet(
    val recipientAddress: String,
    val messageId: String,
    val creationDate: ZonedDateTime,
    val ttl: Int,
    val payload: ByteArray
)

internal class RAMFSerializer(val concreteMessageType: Byte, val concreteMessageVersion: Byte) {
    fun serialize(
        message: RAMFMessage,
        signerPrivateKey: PrivateKey,
        hashingAlgorithm: HashingAlgorithm? = null
    ): ByteArray {
        val output = ByteArrayOutputStream()

        output.write("Relaynet".toByteArray())
        output.write(concreteMessageType.toInt())
        output.write(concreteMessageVersion.toInt())

        val fieldSetSerialized = serializeMessage(message)
        val signedData = sign(
            fieldSetSerialized,
            signerPrivateKey,
            message.senderCertificate,
            message.senderCertificateChain,
            hashingAlgorithm
        )
        output.write(signedData)

        return output.toByteArray()
    }

    @Throws(IOException::class)
    private fun serializeMessage(message: RAMFMessage): ByteArray {
        val reverseOS = ReverseByteArrayOutputStream(1000, true)
        var codeLength = 0

        codeLength += BerOctetString(message.payload).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 4
        reverseOS.write(0x84)
        codeLength += 1

        codeLength += BerInteger(message.ttl.toBigInteger()).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 3
        reverseOS.write(0x83)
        codeLength += 1

        val creationTimeUtc = message.creationDate.withZoneSameInstant(UTC_ZONE_ID)
        codeLength += BerDateTime(creationTimeUtc.format(BER_DATETIME_FORMATTER)).encode(
            reverseOS,
            false
        )
        // write tag: CONTEXT_CLASS, PRIMITIVE, 2
        reverseOS.write(0x82)
        codeLength += 1

        codeLength += BerVisibleString(message.id).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 1
        reverseOS.write(0x81)
        codeLength += 1

        codeLength += BerVisibleString(message.recipientAddress).encode(reverseOS, false)
        // write tag: CONTEXT_CLASS, PRIMITIVE, 0
        reverseOS.write(0x80)
        codeLength += 1

        BerLength.encodeLength(reverseOS, codeLength)
        DER_SEQUENCE_TAG.encode(reverseOS)
        return reverseOS.array
    }

    @Throws(RAMFException::class)
    fun <T> deserialize(
        serialization: ByteArray,
        messageClazz: RAMFMessageConstructor<T>
    ): T {
        return deserialize(serialization.inputStream(), messageClazz)
    }

    @Throws(RAMFException::class)
    fun <T> deserialize(
        serializationStream: InputStream,
        messageClazz: RAMFMessageConstructor<T>
    ): T {
        val serializationSize = serializationStream.available()

        if (OCTETS_IN_9_MIB < serializationSize) {
            throw RAMFException("Message should not be larger than 9 MiB")
        }

        if (serializationSize < 10) {
            throw RAMFException("Serialization is too short to contain format signature")
        }

        val magicConstant = ByteArray(8)
        serializationStream.read(magicConstant, 0, magicConstant.size)
        if (magicConstant.toString(Charset.forName("ASCII")) != "Relaynet") {
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

        val cmsSignedDataResult = try {
            verifySignature(serializationStream.readBytes())
        } catch (exc: SignedDataException) {
            throw RAMFException("Invalid CMS SignedData value", exc)
        }
        val fields = deserializeFields(cmsSignedDataResult.plaintext)
        return messageClazz(
            fields.recipientAddress,
            fields.payload,
            cmsSignedDataResult.signerCertificate,
            fields.messageId,
            fields.creationDate,
            fields.ttl,
            cmsSignedDataResult.attachedCertificates
        )
    }

    @Throws(RAMFException::class)
    private fun deserializeFields(serialization: ByteArray): FieldSet {
        val asn1InputStream = ASN1InputStream(serialization)
        val asn1Value = try {
            asn1InputStream.readObject()
        } catch (_: IOException) {
            throw RAMFException("Message fields are not a DER-encoded")
        }
        val fieldSequence: ASN1Sequence = try {
            ASN1Sequence.getInstance(asn1Value)
        } catch (_: IllegalArgumentException) {
            throw RAMFException("Message fields are not a ASN.1 sequence")
        }
        val fields = fieldSequence.toArray()
        if (fields.size != 5) {
            throw RAMFException(
                "Field sequence should contain 5 items (got ${fields.size})"
            )
        }

        val recipientAddress = DERVisibleString.getInstance(fields[0] as ASN1TaggedObject, false)

        val messageId = DERVisibleString.getInstance(fields[1] as ASN1TaggedObject, false)

        // BouncyCastle doesn't support ASN.1 DATE-TIME values so we have to do the parsing
        // ourselves. We could use a DerGeneralizedTime but that's a bit risky because it may
        // contain a timezone.
        val creationTimeDer = DERVisibleString.getInstance(fields[2] as ASN1TaggedObject, false)
        val creationTime = try {
            LocalDateTime.parse(creationTimeDer.string, BER_DATETIME_FORMATTER)
        } catch (_: DateTimeParseException) {
            throw RAMFException(
                "Creation time should be an ASN.1 DATE-TIME value"
            )
        }

        val ttlDer = ASN1Integer.getInstance(fields[3] as ASN1TaggedObject, false)

        val payloadDer = DEROctetString.getInstance(fields[4] as ASN1TaggedObject, false)

        return FieldSet(
            recipientAddress.string,
            messageId.string,
            ZonedDateTime.of(creationTime, UTC_ZONE_ID),
            ttlDer.intPositiveValueExact(),
            payloadDer.octets
        )
    }
}
