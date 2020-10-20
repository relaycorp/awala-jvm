package tech.relaycorp.relaynet.messages.control

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HandshakeChallengeTest {
    private val nonce = "the nonce".toByteArray()

    @Nested
    inner class Serialize {
        @Test
        fun `Nonce should be serialized`() {
            val challenge = HandshakeChallenge(nonce)

            val serialization = challenge.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val nonceASN1 = ASN1Utils.getOctetString(sequenceASN1.first())
            assertEquals(nonce.asList(), nonceASN1.octets.asList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be a DER sequence`() {
            val exception = assertThrows<InvalidMessageException> {
                HandshakeChallenge.deserialize(byteArrayOf(0))
            }

            assertEquals("Handshake challenge is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least one item`() {
            val invalidSequence = ASN1Utils.serializeSequence(arrayOf(), false)

            val exception = assertThrows<InvalidMessageException> {
                HandshakeChallenge.deserialize(invalidSequence)
            }

            assertEquals(
                "Handshake challenge sequence should have at least 1 item",
                exception.message
            )
        }

        @Test
        fun `Valid challenges should be accepted`() {
            val challenge = HandshakeChallenge(nonce)
            val serialization = challenge.serialize()

            val challengeDeserialized = HandshakeChallenge.deserialize(serialization)

            assertEquals(nonce.asList(), challengeDeserialized.nonce.asList())
        }
    }
}
