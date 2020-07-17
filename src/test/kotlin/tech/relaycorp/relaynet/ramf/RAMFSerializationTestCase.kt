package tech.relaycorp.relaynet.ramf

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.time.ZonedDateTime
import kotlin.test.assertEquals

typealias MinimalRAMFMessageConstructor<M> = (String, ByteArray, Certificate) -> M

internal abstract class RAMFSerializationTestCase<M : RAMFMessage<*>>(
    private val messageConstructor: RAMFMessageConstructor<M>,
    requiredParamsConstructor: MinimalRAMFMessageConstructor<M>,
    private val expectedConcreteMessageType: Byte,
    private val expectedConcreteMessageVersion: Byte,
    private val companion: RAMFMessageCompanion<M>
) {
    val simpleMessage = requiredParamsConstructor(recipientAddress, payload, senderCertificate)

    @Nested
    inner class Serialization {
        @Test
        fun `Recipient address should be honored`() {
            assertEquals(recipientAddress, simpleMessage.recipientAddress)
        }

        @Test
        fun `Payload should be honored`() {
            assertEquals(payload, simpleMessage.payload)
        }

        @Test
        fun `Sender certificate should be honored`() {
            assertEquals(senderCertificate, simpleMessage.senderCertificate)
        }

        @Test
        fun `Serializer should be configured to use specified message type and version`() {
            val messageSerialized = simpleMessage.serialize(keyPair.private)

            assertEquals(expectedConcreteMessageType, messageSerialized[8])
            assertEquals(expectedConcreteMessageVersion, messageSerialized[9])
        }

        @Test
        fun `Message id should be honored if set`() {
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
        }

        @Test
        fun `Creation time should be honored if set`() {
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
        }

        @Test
        fun `TTL should be honored if set`() {
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
        }

        @Test
        fun `Sender certificate chain should be honored if set`() {
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
    }

    @Nested
    inner class Deserialization {
        private val messageSerialized = simpleMessage.serialize(keyPair.private)

        @Test
        fun `Valid ByteArray should be deserialized`() {
            val ccaDeserialized = companion.deserialize(messageSerialized)

            assertEquals(simpleMessage.id, ccaDeserialized.id)
        }

        @Test
        fun `Valid InputStream should be deserialized`() {
            val ccaDeserialized = companion.deserialize(messageSerialized.inputStream())

            assertEquals(simpleMessage.id, ccaDeserialized.id)
        }
    }

    companion object {
        private const val recipientAddress = "0deadbeef"
        private val payload = "Payload".toByteArray()
        private val keyPair = generateRSAKeyPair()
        private val senderCertificate = issueStubCertificate(keyPair.public, keyPair.private)
    }
}
