package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.BerLength
import com.beanit.jasn1.ber.BerTag
import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerGeneralizedTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.BerType
import com.beanit.jasn1.ber.types.string.BerVisibleString
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.utils.BER_DATETIME_FORMATTER
import tech.relaycorp.relaynet.utils.StubEncryptedRAMFMessage
import tech.relaycorp.relaynet.utils.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.cms.parseCmsSignedData
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair

// Pick a timezone that's never equivalent to UTC (unlike "Europe/London")
val NON_UTC_ZONE_ID: ZoneId = ZoneId.of("America/Caracas")

class RAMFSerializerTest {
    private val stubCaSenderKeyPair = generateRSAKeyPair()
    private val stubCaCertificate = issueStubCertificate(
        stubCaSenderKeyPair.public,
        stubCaSenderKeyPair.private,
        isCA = true
    )
    val stubSenderCertificateChain = setOf(stubCaCertificate)

    private val stubSenderKeyPair = generateRSAKeyPair()
    private val stubSenderCertificate = issueStubCertificate(
        stubSenderKeyPair.public,
        stubCaSenderKeyPair.private,
        stubCaCertificate
    )

    private val stubMessage = StubEncryptedRAMFMessage(
        "04334",
        "payload".toByteArray(),
        stubSenderCertificate,
        "message-id",
        ZonedDateTime.now(ZoneId.of("UTC")),
        12345,
        stubSenderCertificateChain
    )

    private val serializer = StubEncryptedRAMFMessage.SERIALIZER

    private val stubSerialization = serializer.serialize(
        stubMessage,
        stubSenderKeyPair.private
    )

    @Nested
    inner class Serialize {
        @Test
        fun `Magic constant should be ASCII string Relaynet`() {
            val magicSignature = stubSerialization.copyOfRange(0, 8)
            assertEquals("Relaynet", magicSignature.toString(Charset.forName("ASCII")))
        }

        @Test
        fun `Concrete message type should be set`() {
            assertEquals(
                serializer.concreteMessageType,
                stubSerialization[8]
            )
        }

        @Test
        fun `Concrete message version should be set`() {
            assertEquals(
                serializer.concreteMessageVersion,
                stubSerialization[9]
            )
        }

        @Nested
        inner class SignedDataValue {
            @Test
            fun `Message fields should be wrapped in a CMS SignedData value`() {
                val cmsSignedDataSerialized = skipFormatSignature(stubSerialization)

                val cmsSignedData = SignedData.deserialize(cmsSignedDataSerialized)
                cmsSignedData.verify()
            }

            @Test
            fun `Sender certificate should be encapsulated`() {
                val cmsSignedDataSerialized = skipFormatSignature(stubSerialization)

                val cmsSignedData = SignedData.deserialize(cmsSignedDataSerialized)
                assertEquals(
                    stubSenderCertificate,
                    cmsSignedData.signerCertificate
                )
            }

            @Test
            fun `Sender certificate chain should be encapsulated`() {
                val cmsSignedDataSerialized = skipFormatSignature(stubSerialization)

                val cmsSignedData = SignedData.deserialize(cmsSignedDataSerialized)
                assertEquals(
                    stubSenderCertificateChain.union(setOf(stubSenderCertificate)),
                    cmsSignedData.certificates
                )
            }

            @Nested
            inner class Hashing {
                @Test
                fun `SHA-256 should be used by default`() {
                    val cmsSignedDataSerialized = skipFormatSignature(stubSerialization)

                    val cmsSignedData = parseCmsSignedData(cmsSignedDataSerialized)

                    assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
                    assertEquals(
                        HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA256],
                        cmsSignedData.digestAlgorithmIDs.first().algorithm
                    )
                }

                @Test
                fun `Hashing algorithm should be customizable`() {
                    val serialization = serializer.serialize(
                        stubMessage,
                        stubSenderKeyPair.private,
                        hashingAlgorithm = HashingAlgorithm.SHA384
                    )
                    val signedDataSerialized = skipFormatSignature(serialization)

                    val signedData = parseCmsSignedData(signedDataSerialized)

                    assertEquals(1, signedData.digestAlgorithmIDs.size)
                    assertEquals(
                        HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA384],
                        signedData.digestAlgorithmIDs.first().algorithm
                    )
                }
            }
        }

        @Nested
        inner class FieldSet {
            @Test
            fun `Recipient should be stored as an ASN1 VisibleString`() {
                val sequence = getFieldSequence(stubSerialization)
                val recipientDer = ASN1Utils.getVisibleString(sequence[0])
                assertEquals(stubMessage.recipientAddress, recipientDer.string)
            }

            @Test
            fun `Message id should be stored as an ASN1 VisibleString`() {
                val sequence = getFieldSequence(stubSerialization)
                val messageIdDer = ASN1Utils.getVisibleString(sequence[1])
                assertEquals(stubMessage.id, messageIdDer.string)
            }

            @Nested
            inner class CreationDate {
                @Test
                fun `Creation date should be stored as an ASN1 DateTime`() {
                    val sequence = getFieldSequence(stubSerialization)
                    val creationTimeRaw = sequence[2]
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        stubMessage.creationDate.format(BER_DATETIME_FORMATTER),
                        creationTimeDer.timeString
                    )
                }

                @Test
                fun `Creation date should be converted to UTC when provided in different TZ`() {
                    val nowTimezoneUnaware = LocalDateTime.now()
                    val message = StubEncryptedRAMFMessage(
                        stubMessage.recipientAddress,
                        stubMessage.payload,
                        stubSenderCertificate,
                        stubMessage.id,
                        ZonedDateTime.of(nowTimezoneUnaware, NON_UTC_ZONE_ID),
                        stubMessage.ttl,
                        stubSenderCertificateChain
                    )
                    val messageSerialized = serializer.serialize(
                        message,
                        stubSenderKeyPair.private
                    )

                    val sequence = getFieldSequence(messageSerialized)

                    val creationTimeRaw = sequence[2]
                    // We should technically be using a DateTime type instead of GeneralizedTime, but BC
                    // doesn't support it.
                    val creationTimeDer = DERGeneralizedTime.getInstance(creationTimeRaw, false)
                    assertEquals(
                        message.creationDate.withZoneSameInstant(ZoneId.of("UTC"))
                            .format(BER_DATETIME_FORMATTER),
                        creationTimeDer.timeString
                    )
                }
            }

            @Test
            fun `TTL should be stored as an ASN1 Integer`() {
                val sequence = getFieldSequence(stubSerialization)
                val ttlDer = ASN1Integer.getInstance(sequence[3], false)
                assertEquals(stubMessage.ttl, ttlDer.intPositiveValueExact())
            }

            @Test
            fun `Payload should be stored as an ASN1 Octet String`() {
                val sequence = getFieldSequence(stubSerialization)
                val payloadDer = ASN1Utils.getOctetString(sequence[4])
                assertEquals(stubMessage.payload.asList(), payloadDer.octets.asList())
            }

            private fun getFieldSequence(serialization: ByteArray): Array<ASN1TaggedObject> {
                val signedDataSerialized = skipFormatSignature(serialization)
                val signedData = SignedData.deserialize(signedDataSerialized)
                assertNotNull(signedData.plaintext)
                return ASN1Utils.deserializeHeterogeneousSequence(signedData.plaintext!!)
            }
        }
    }

    @Nested
    inner class Deserialize {
        private val octetsIn9Mib = 9437184

        @Test
        fun `Messages up to 9 MiB should be accepted`() {
            val invalidSerialization = "a".repeat(octetsIn9Mib).toByteArray()

            // Deserialization still fails, but for a different reason
            val exception = assertThrows<RAMFException> {
                serializer.deserialize(
                    invalidSerialization,
                    ::StubEncryptedRAMFMessage
                )
            }
            assertEquals(
                "Format signature should start with magic constant 'Relaynet'",
                exception.message
            )
        }

        @Test
        fun `Messages larger than 9 MiB should be refused`() {
            val invalidSerialization = "a".repeat(octetsIn9Mib + 1).toByteArray()

            val exception =
                assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization,
                        ::StubEncryptedRAMFMessage
                    )
                }

            assertEquals("Message should not be larger than 9 MiB", exception.message)
        }

        @Test
        fun `Input can be a ByteArray`() {
            @Suppress("USELESS_IS_CHECK")
            assertTrue(stubSerialization is ByteArray)

            val message = serializer.deserialize(
                stubSerialization,
                ::StubEncryptedRAMFMessage
            )

            assertEquals(stubMessage.recipientAddress, message.recipientAddress)
        }

        @Test
        fun `Input can be an InputStream`() {
            val message = serializer.deserialize(
                stubSerialization.inputStream(),
                ::StubEncryptedRAMFMessage
            )

            assertEquals(stubMessage.recipientAddress, message.recipientAddress)
        }

        @Nested
        inner class FormatSignature {
            @Test
            fun `Format signature must be present`() {
                val formatSignatureLength = 10
                val invalidSerialization = "a".repeat(formatSignatureLength - 1).toByteArray()

                val exception =
                    assertThrows<RAMFException> {
                        serializer.deserialize(
                            invalidSerialization,
                            ::StubEncryptedRAMFMessage
                        )
                    }

                assertEquals(
                    "Serialization is too short to contain format signature",
                    exception.message
                )
            }

            @Test
            fun `Magic constant should be ASCII string Relaynet`() {
                val incompleteSerialization = "Relaynope01234".toByteArray()

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        incompleteSerialization,
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals(
                    "Format signature should start with magic constant 'Relaynet'",
                    exception.message
                )
            }

            @Test
            fun `Concrete message type should match expected one`() {
                val invalidMessageType = serializer.concreteMessageType.inc()
                val invalidSerialization = ByteArrayOutputStream(10)
                invalidSerialization.write("Relaynet".toByteArray())
                invalidSerialization.write(invalidMessageType.toInt())
                invalidSerialization.write(serializer.concreteMessageVersion.toInt())

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals(
                    "Message type should be ${serializer.concreteMessageType} " +
                        "(got $invalidMessageType)",
                    exception.message
                )
            }

            @Test
            fun `Concrete message version should match expected one`() {
                val invalidMessageVersion = serializer.concreteMessageVersion.inc()
                val invalidSerialization = ByteArrayOutputStream(10)
                invalidSerialization.write("Relaynet".toByteArray())
                invalidSerialization.write(serializer.concreteMessageType.toInt())
                invalidSerialization.write(invalidMessageVersion.toInt())

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals(
                    "Message version should be ${serializer.concreteMessageVersion} " +
                        "(got $invalidMessageVersion)",
                    exception.message
                )
            }
        }

        @Nested
        inner class Signature {
            @Test
            fun `Invalid signature should be refused`() {
                val invalidSerialization = ByteArrayOutputStream()
                invalidSerialization.write("Relaynet".toByteArray())
                invalidSerialization.write(serializer.concreteMessageType.toInt())
                invalidSerialization.write(serializer.concreteMessageVersion.toInt())
                invalidSerialization.write("Not really CMS SignedData".toByteArray())

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals("Invalid CMS SignedData value", exception.message)
                assertTrue(exception.cause is SignedDataException)
                assertEquals("Value is not DER-encoded", exception.cause?.message)
            }

            @Test
            fun `Message should take sender certificate from valid SignedData value`() {
                val messageDeserialized =
                    serializer.deserialize(
                        stubSerialization,
                        ::StubEncryptedRAMFMessage
                    )

                assertEquals(stubSenderCertificate, messageDeserialized.senderCertificate)
            }

            @Test
            fun `Message should take sender certificate chain from valid SignedData value`() {
                val messageDeserialized =
                    serializer.deserialize(
                        stubSerialization,
                        ::StubEncryptedRAMFMessage
                    )

                assertEquals(
                    stubSenderCertificateChain,
                    messageDeserialized.senderCertificateChain
                )
            }
        }

        @Nested
        inner class FieldSet {
            private val formatSignature: ByteArray = "Relaynet".toByteArray() + byteArrayOf(
                serializer.concreteMessageType,
                serializer.concreteMessageVersion
            )

            @Test
            fun `Fields should be DER-serialized`() {
                val invalidSerialization = ByteArrayOutputStream(11)
                invalidSerialization.write(formatSignature)
                invalidSerialization.write(
                    SignedData.sign(
                        "not DER".toByteArray(),
                        stubSenderKeyPair.private,
                        stubSenderCertificate,
                        setOf(stubSenderCertificate)
                    ).serialize()
                )

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals("Invalid RAMF message", exception.message)
                assertNotNull(exception.cause)
                assertEquals("Value is not DER-encoded", exception.cause!!.message)
            }

            @Test
            fun `Fields should be stored as a universal, constructed sequence`() {
                val invalidSerialization = ByteArrayOutputStream(11)
                invalidSerialization.write(formatSignature)

                val fieldSetSerialization = ReverseByteArrayOutputStream(100)
                BerOctetString("Not a sequence".toByteArray()).encode(fieldSetSerialization)
                invalidSerialization.write(
                    SignedData.sign(
                        fieldSetSerialization.array,
                        stubSenderKeyPair.private,
                        stubSenderCertificate,
                        setOf(stubSenderCertificate)
                    ).serialize()
                )

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals("Invalid RAMF message", exception.message)
                assertNotNull(exception.cause)
                assertEquals("Value is not an ASN.1 sequence", exception.cause!!.message)
            }

            @Test
            fun `Fields should be a sequence of exactly 5 items`() {
                val invalidSerialization = ByteArrayOutputStream()
                invalidSerialization.write(formatSignature)

                val fieldSetSerialization = serializeSequence(
                    BerVisibleString("1"),
                    BerVisibleString("2"),
                    BerVisibleString("3"),
                    BerVisibleString("4"),
                    BerVisibleString("5"),
                    BerVisibleString("6")
                )
                invalidSerialization.write(
                    SignedData.sign(
                        fieldSetSerialization,
                        stubSenderKeyPair.private,
                        stubSenderCertificate,
                        setOf(stubSenderCertificate)
                    ).serialize()
                )

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals(
                    "Field sequence should contain 5 items (got 6)",
                    exception.message
                )
            }

            @Test
            fun `Message fields should be output when the serialization is valid`() {
                val serialization = serializer.serialize(
                    stubMessage,
                    stubSenderKeyPair.private
                )

                val parsedMessage =
                    serializer.deserialize(
                        serialization,
                        ::StubEncryptedRAMFMessage
                    )

                assertEquals(stubMessage.recipientAddress, parsedMessage.recipientAddress)

                assertEquals(stubMessage.id, parsedMessage.id)

                assertEquals(
                    stubMessage.creationDate.withNano(0),
                    parsedMessage.creationDate
                )

                assertEquals(stubMessage.ttl, parsedMessage.ttl)

                assertEquals(stubMessage.payload.asList(), parsedMessage.payload.asList())
            }

            @Test
            fun `Creation time in a format other than ASN1 DATE-TIME should be refused`() {
                // For example, a GeneralizedTime value (which includes timezone) should be refused
                val invalidSerialization = ByteArrayOutputStream()
                invalidSerialization.write(formatSignature)

                val fieldSetSerialization =
                    serializeFieldSet(creationTime = BerGeneralizedTime("20200307173323-03"))
                invalidSerialization.write(
                    SignedData.sign(
                        fieldSetSerialization,
                        stubSenderKeyPair.private,
                        stubSenderCertificate,
                        setOf(stubSenderCertificate)
                    ).serialize()
                )

                val exception = assertThrows<RAMFException> {
                    serializer.deserialize(
                        invalidSerialization.toByteArray(),
                        ::StubEncryptedRAMFMessage
                    )
                }

                assertEquals(
                    "Creation time should be an ASN.1 DATE-TIME value",
                    exception.message
                )
            }

            @Test
            fun `Creation time should be parsed as UTC`() {
                val message = StubEncryptedRAMFMessage(
                    stubMessage.recipientAddress,
                    stubMessage.payload,
                    stubSenderCertificate,
                    stubMessage.id,
                    stubMessage.creationDate.withZoneSameInstant(NON_UTC_ZONE_ID),
                    stubMessage.ttl,
                    stubSenderCertificateChain
                )
                val serialization = serializer.serialize(
                    message,
                    stubSenderKeyPair.private
                )

                val parsedMessage =
                    serializer.deserialize(
                        serialization,
                        ::StubEncryptedRAMFMessage
                    )

                assertEquals(parsedMessage.creationDate.zone, ZoneId.of("UTC"))
            }

            private fun serializeFieldSet(
                recipientAddress: BerType = BerVisibleString(stubMessage.recipientAddress),
                messageId: BerType = BerVisibleString(stubMessage.id),
                creationTime: BerType = BerDateTime(
                    stubMessage.creationDate.format(
                        BER_DATETIME_FORMATTER
                    )
                ),
                ttl: BerType = BerInteger(stubMessage.ttl.toBigInteger()),
                payload: BerType = BerOctetString(stubMessage.payload)
            ): ByteArray {
                return serializeSequence(
                    recipientAddress,
                    messageId,
                    creationTime,
                    ttl,
                    payload
                )
            }

            private fun serializeSequence(
                vararg items: BerType
            ): ByteArray {
                val reverseOS = ReverseByteArrayOutputStream(256, true)
                val lastIndex = 0x80 + items.size - 1
                val serializationLength =
                    items.reversed()
                        .mapIndexed { i, v -> serializeItem(v, reverseOS, lastIndex - i) }.sum()

                BerLength.encodeLength(reverseOS, serializationLength)
                BerTag(BerTag.UNIVERSAL_CLASS, BerTag.CONSTRUCTED, 16).encode(reverseOS)
                return reverseOS.array
            }

            private fun serializeItem(
                item: BerType,
                reverseOS: ReverseByteArrayOutputStream,
                index: Int
            ): Int {
                val length = when (item) {
                    is BerVisibleString -> item.encode(reverseOS, false)
                    is BerInteger -> item.encode(reverseOS, false)
                    is BerOctetString -> item.encode(reverseOS, false)
                    else -> throw Exception("Unsupported BER type")
                }
                reverseOS.write(index)
                return length + 1
            }
        }
    }

    @Test
    fun `formatSignature should contain the type and version`() {
        assertEquals(
            byteArrayOf(
                *"Relaynet".toByteArray(),
                serializer.concreteMessageType,
                serializer.concreteMessageVersion
            ).asList(),
            serializer.formatSignature.asList()
        )
    }
}
