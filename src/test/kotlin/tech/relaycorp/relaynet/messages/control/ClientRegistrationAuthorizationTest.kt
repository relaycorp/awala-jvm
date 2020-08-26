package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.BER_DATETIME_FORMATTER
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.RSASigning
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ClientRegistrationAuthorizationTest {
    private val tomorrow = ZonedDateTime.now().plusDays(1)
    private val serverData = "this is opaque to the client".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Serialize {
        @Test
        fun `Expiry date should be honored`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val expiryDateDer = DERGeneralizedTime.getInstance(sequence[0], false)
            val expectedDate =
                tomorrow.withZoneSameInstant(ZoneOffset.UTC).format(BER_DATETIME_FORMATTER)
            assertEquals(expectedDate, expiryDateDer.timeString)
        }

        @Test
        fun `Server data should be honored`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val actualServerData = ASN1OctetString.getInstance(sequence[1], false)
            assertEquals(serverData.asList(), actualServerData.octets.asList())
        }

        @Test
        fun `Signature should be valid`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val signature = ASN1Utils.getOctetString(sequence[2]).octets
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(OIDs.CRA, ASN1Utils.derEncodeUTCDate(tomorrow), DEROctetString(serverData)),
                false
            )
            assertTrue(RSASigning.verify(signature, keyPair.public, expectedPlaintext))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Malformed values should be refused`() {
            val serialization = "invalid".toByteArray()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("CRA is not a valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least 3 items`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(DERVisibleString("a"), DERVisibleString("b")),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals(
                "CRA plaintext should have at least 3 items (got 2)",
                exception.message
            )
        }

        @Test
        fun `Expired authorizations should be refused`() {
            val oneSecondAgo = ZonedDateTime.now().minusSeconds(1)
            val authorization = ClientRegistrationAuthorization(oneSecondAgo, serverData)
            val serialization = authorization.serialize(keyPair.private)

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("CRA already expired", exception.message)
        }

        @Test
        fun `Invalid signatures should be refused`() {
            val invalidSignature = "not a valid signature".toByteArray()
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    ASN1Utils.derEncodeUTCDate(tomorrow),
                    DEROctetString(serverData),
                    DEROctetString(invalidSignature)
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("CRA signature is invalid", exception.message)
        }

        @Test
        fun `Valid values should be accepted`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)
            val serialization = authorization.serialize(keyPair.private)

            val authorizationDeserialized =
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)

            assertEquals(tomorrow.withNano(0), authorizationDeserialized.expiryDate)
            assertEquals(serverData.asList(), authorizationDeserialized.serverData.asList())
        }
    }
}
