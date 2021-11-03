package tech.relaycorp.relaynet.messages.control

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class HandshakeResponseTest {
    val nonceSignature = "the nonce signature".toByteArray()

    @Nested
    inner class Serialize {
        @Test
        fun `Zero nonce signatures should result in an empty sequence`() {
            val response = HandshakeResponse(listOf())

            val serialization = response.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val nonceSignaturesASN1 = DERSequence.getInstance(sequenceASN1.first(), false)
            assertEquals(0, nonceSignaturesASN1.size())
        }

        @Test
        fun `Nonce signatures should be serialized`() {
            val response = HandshakeResponse(listOf(nonceSignature))

            val serialization = response.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val nonceSignaturesASN1 = DERSequence.getInstance(sequenceASN1.first(), false)
            assertEquals(1, nonceSignaturesASN1.size())
            assertEquals(
                listOf(nonceSignature.asList()),
                nonceSignaturesASN1.objects.asSequence()
                    .map { (it as DEROctetString).octets.asList() }
                    .toList()
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be a DER sequence`() {
            val exception = assertThrows<InvalidMessageException> {
                HandshakeResponse.deserialize(byteArrayOf(0))
            }

            assertEquals("Handshake response is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least one item`() {
            val invalidSequence = ASN1Utils.serializeSequence(listOf(), false)

            val exception = assertThrows<InvalidMessageException> {
                HandshakeResponse.deserialize(invalidSequence)
            }

            assertEquals(
                "Handshake response sequence should have at least 1 item",
                exception.message
            )
        }

        @Test
        fun `Valid responses should be accepted`() {
            val response = HandshakeResponse(listOf(nonceSignature))
            val serialization = response.serialize()

            val responseDeserialized = HandshakeResponse.deserialize(serialization)

            assertEquals(1, responseDeserialized.nonceSignatures.size)
            assertEquals(
                nonceSignature.toList(),
                responseDeserialized.nonceSignatures.first().toList()
            )
        }
    }
}
