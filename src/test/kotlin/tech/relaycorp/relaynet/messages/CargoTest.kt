package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals

class CargoTest {
    private val recipientAddress = "0deadbeef"
    private val payload = "Payload".toByteArray()
    private val keyPair = generateRSAKeyPair()
    private val senderCertificate = issueStubCertificate(keyPair.public, keyPair.private)

    @Nested
    inner class Constructor {
        @Test
        fun `Recipient address should be honored`() {
            val cargo = Cargo(recipientAddress, payload, senderCertificate)

            assertEquals(recipientAddress, cargo.recipientAddress)
        }

        @Test
        fun `Payload should be honored`() {
            val cargo = Cargo(recipientAddress, payload, senderCertificate)

            assertEquals(payload, cargo.payload)
        }

        @Test
        fun `Sender certificate should be honored`() {
            val cargo = Cargo(recipientAddress, payload, senderCertificate)

            assertEquals(senderCertificate, cargo.senderCertificate)
        }

        @Test
        fun `Serializer should be configured to use message type 0x43 and version 0x00`() {
            val cargo = Cargo(recipientAddress, payload, senderCertificate)

            val cargoSerialized = cargo.serialize(keyPair.private)

            assertEquals(0x43, cargoSerialized[8])
            assertEquals(0x00, cargoSerialized[9])
        }

        @Test
        fun `Message id should be honored if set`() {
            val messageId = "the-id"
            val cargo = Cargo(recipientAddress, payload, senderCertificate, messageId = messageId)

            assertEquals(messageId, cargo.messageId)
        }

        @Test
        fun `Creation time should be honored if set`() {
            val creationDate = ZonedDateTime.now().minusMinutes(10)
            val cargo =
                Cargo(recipientAddress, payload, senderCertificate, creationDate = creationDate)

            assertEquals(creationDate, cargo.creationDate)
        }

        @Test
        fun `TTL should be honored if set`() {
            val ttl = 42
            val cargo = Cargo(recipientAddress, payload, senderCertificate, ttl = ttl)

            assertEquals(ttl, cargo.ttl)
        }

        @Test
        fun `Sender certificate chain should be honored if set`() {
            val senderCertificateChain = setOf(
                issueStubCertificate(keyPair.public, keyPair.private)
            )
            val cargo = Cargo(
                recipientAddress,
                payload,
                senderCertificate,
                senderCertificateChain = senderCertificateChain
            )

            assertEquals(senderCertificateChain, cargo.senderCertificateChain)
        }
    }

    @Nested
    inner class Companion {
        @Nested
        inner class Deserialize {
            @Test
            fun `Deserializer should be configured to use message type 0x43 and version 0x00`() {
                val cargo = Cargo(recipientAddress, payload, senderCertificate)
                val cargoSerialized = cargo.serialize(keyPair.private)

                val cargoDeserialized = Cargo.deserialize(cargoSerialized)

                assertEquals(cargo.messageId, cargoDeserialized.messageId)
            }
        }
    }
}
