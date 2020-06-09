package tech.relaycorp.relaynet.ramf

import org.junit.jupiter.api.DynamicTest
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.time.ZonedDateTime
import kotlin.test.assertEquals

private const val recipientAddress = "0deadbeef"
private val payload = "Payload".toByteArray()
private val keyPair = generateRSAKeyPair()
private val senderCertificate = issueStubCertificate(keyPair.public, keyPair.private)

typealias MinimalRAMFMessageConstructor<M> = (String, ByteArray, Certificate) -> M

fun <M : RAMFMessage> makeRAMFMessageConstructorTests(
    messageConstructor: RAMFMessageConstructor<M>,
    requiredParamsConstructor: MinimalRAMFMessageConstructor<M>,
    expectedConcreteMessageType: Byte,
    expectedConcreteMessageVersion: Byte
): Collection<DynamicTest> {
    val simpleMessage = requiredParamsConstructor(recipientAddress, payload, senderCertificate)

    return listOf(
        DynamicTest.dynamicTest("Recipient address should be honored") {
            assertEquals(recipientAddress, simpleMessage.recipientAddress)
        },
        DynamicTest.dynamicTest("Payload should be honored") {
            assertEquals(payload, simpleMessage.payload)
        },
        DynamicTest.dynamicTest("Sender certificate should be honored") {
            assertEquals(senderCertificate, simpleMessage.senderCertificate)
        },
        DynamicTest.dynamicTest(
            "Serializer should be configured to use specified message type and version"
        ) {
            val messageSerialized = simpleMessage.serialize(keyPair.private)

            assertEquals(expectedConcreteMessageType, messageSerialized[8])
            assertEquals(expectedConcreteMessageVersion, messageSerialized[9])
        },
        DynamicTest.dynamicTest("Message id should be honored if set") {
            val messageId = "the-id"
            val message = messageConstructor(
                recipientAddress,
                payload,
                senderCertificate,
                messageId,
                null,
                null,
                null
            )

            assertEquals(messageId, message.id)
        },
        DynamicTest.dynamicTest("Creation time should be honored if set") {
            val creationDate = ZonedDateTime.now().minusMinutes(10)
            val message =
                messageConstructor(
                    recipientAddress,
                    payload,
                    senderCertificate,
                    null,
                    creationDate,
                    null,
                    null
                )

            assertEquals(creationDate, message.creationDate)
        },
        DynamicTest.dynamicTest("TTL should be honored if set") {
            val ttl = 42
            val message =
                messageConstructor(
                    recipientAddress,
                    payload,
                    senderCertificate,
                    null,
                    null,
                    ttl,
                    null
                )

            assertEquals(ttl, message.ttl)
        },
        DynamicTest.dynamicTest("Sender certificate chain should be honored if set") {
            val senderCertificateChain = setOf(
                issueStubCertificate(keyPair.public, keyPair.private)
            )
            val message = messageConstructor(
                recipientAddress,
                payload,
                senderCertificate,
                null,
                null,
                null,
                senderCertificateChain
            )

            assertEquals(senderCertificateChain, message.senderCertificateChain)
        }
    )
}

internal fun <M : RAMFMessage> makeRAMFMessageCompanionTests(
    companion: RAMFMessageCompanion<M>,
    messageConstructor: RAMFMessageConstructor<M>
): Collection<DynamicTest> {
    val message =
        messageConstructor(recipientAddress, payload, senderCertificate, null, null, null, null)
    val messageSerialized = message.serialize(keyPair.private)

    return listOf(
        DynamicTest.dynamicTest("Valid ByteArray should be deserialized") {
            val ccaDeserialized = companion.deserialize(messageSerialized)

            assertEquals(message.id, ccaDeserialized.id)
        },
        DynamicTest.dynamicTest("Valid InputStream should be deserialized") {
            val ccaDeserialized = companion.deserialize(messageSerialized.inputStream())

            assertEquals(message.id, ccaDeserialized.id)
        }
    )
}
