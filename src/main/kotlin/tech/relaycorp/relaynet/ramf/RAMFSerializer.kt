package tech.relaycorp.relaynet.ramf

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.Charset
import java.security.PrivateKey
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeParseException
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

private const val OCTETS_IN_9_MIB = 9437184

private val UTC_ZONE_ID: ZoneId = ZoneId.of("UTC")

@Suppress("ArrayInDataClass")
private data class FieldSet(
    val recipient: Recipient,
    val messageId: String,
    val creationDate: ZonedDateTime,
    val ttl: Int,
    val payload: ByteArray,
)

internal class RAMFSerializer(val concreteMessageType: Byte, val concreteMessageVersion: Byte) {
    val formatSignature =
        byteArrayOf(*"Awala".toByteArray(), concreteMessageType, concreteMessageVersion)

    fun serialize(
        message: RAMFMessage<*>,
        signerPrivateKey: PrivateKey,
        hashingAlgorithm: HashingAlgorithm? = null,
    ): ByteArray {
        val output = ByteArrayOutputStream()

        output.write(formatSignature)

        val fieldSetSerialized = serializeMessage(message)
        val signedData =
            SignedData.sign(
                fieldSetSerialized,
                signerPrivateKey,
                message.senderCertificate,
                setOf(message.senderCertificate) + message.senderCertificateChain,
                hashingAlgorithm,
            )
        output.write(signedData.serialize())

        return output.toByteArray()
    }

    @Throws(IOException::class)
    private fun serializeMessage(message: RAMFMessage<*>): ByteArray {
        val creationTimeUtc = message.creationDate.withZoneSameInstant(UTC_ZONE_ID)
        val creationTimeUtcString = creationTimeUtc.format(ASN1Utils.BER_DATETIME_FORMATTER)
        return ASN1Utils.serializeSequence(
            listOf(
                message.recipient.serialize(),
                DERVisibleString(message.id),
                DERGeneralizedTime(creationTimeUtcString),
                ASN1Integer(message.ttl.toLong()),
                DEROctetString(message.payload),
            ),
            false,
        )
    }

    @Throws(RAMFException::class)
    fun <T> deserialize(
        serialization: ByteArray,
        messageClazz: RAMFMessageConstructor<T>,
    ): T {
        return deserialize(serialization.inputStream(), messageClazz)
    }

    @Throws(RAMFException::class)
    fun <T> deserialize(
        serializationStream: InputStream,
        messageClazz: RAMFMessageConstructor<T>,
    ): T {
        val serializationSize = serializationStream.available()

        if (OCTETS_IN_9_MIB < serializationSize) {
            throw RAMFException("Message should not be larger than 9 MiB")
        }

        if (serializationSize < 7) {
            throw RAMFException("Serialization is too short to contain format signature")
        }

        val magicConstant = ByteArray(5)
        serializationStream.read(magicConstant, 0, magicConstant.size)
        if (magicConstant.toString(Charset.forName("ASCII")) != "Awala") {
            throw RAMFException("Format signature should start with magic constant 'Awala'")
        }

        val messageType = serializationStream.read()
        if (messageType != concreteMessageType.toInt()) {
            throw RAMFException(
                "Message type should be $concreteMessageType (got $messageType)",
            )
        }

        val messageVersion = serializationStream.read()
        if (messageVersion != concreteMessageVersion.toInt()) {
            throw RAMFException(
                "Message version should be $concreteMessageVersion (got $messageVersion)",
            )
        }

        val cmsSignedData =
            try {
                SignedData.deserialize(serializationStream.readBytes()).also { it.verify() }
            } catch (exc: SignedDataException) {
                throw RAMFException("Invalid CMS SignedData value", exc)
            }
        val fields = deserializeFields(cmsSignedData.plaintext!!)
        val intermediateCACerts =
            cmsSignedData.certificates.filter {
                it != cmsSignedData.signerCertificate
            }.toSet()
        return messageClazz(
            fields.recipient,
            fields.payload,
            // Verification passed, so the cert is present
            cmsSignedData.signerCertificate!!,
            fields.messageId,
            fields.creationDate,
            fields.ttl,
            intermediateCACerts,
        )
    }

    @Throws(RAMFException::class)
    private fun deserializeFields(serialization: ByteArray): FieldSet {
        val fields =
            try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw RAMFException("Invalid RAMF message", exc)
            }
        if (fields.size != 5) {
            throw RAMFException(
                "Field sequence should contain 5 items (got ${fields.size})",
            )
        }

        val recipient = Recipient.deserialize(fields[0])

        val messageId = ASN1Utils.getVisibleString(fields[1])

        // BouncyCastle doesn't support ASN.1 DATE-TIME values so we have to do the parsing
        // ourselves. We could use a DerGeneralizedTime but that's a bit risky because it may
        // contain a timezone.
        val creationTimeDer = ASN1Utils.getVisibleString(fields[2])
        val creationTime =
            try {
                LocalDateTime.parse(creationTimeDer.string, ASN1Utils.BER_DATETIME_FORMATTER)
            } catch (_: DateTimeParseException) {
                throw RAMFException(
                    "Creation time should be an ASN.1 DATE-TIME value",
                )
            }

        val ttlDer = ASN1Integer.getInstance(fields[3], false)

        val payloadDer = ASN1Utils.getOctetString(fields[4])

        return FieldSet(
            recipient,
            messageId.string,
            ZonedDateTime.of(creationTime, UTC_ZONE_ID),
            ttlDer.intPositiveValueExact(),
            payloadDer.octets,
        )
    }
}
