package tech.relaycorp.relaynet.messages.control

import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue
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

class PrivateNodeRegistrationAuthorizationTest {
    private val tomorrow = ZonedDateTime.now().plusDays(1)
    private val gatewayData = "this is opaque to the private node".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Serialize {
        @Test
        fun `Expiry date should be honored`() {
            val authorization = PrivateNodeRegistrationAuthorization(tomorrow, gatewayData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val expiryDateDer = DERGeneralizedTime.getInstance(sequence[0], false)
            val expectedDate =
                tomorrow.withZoneSameInstant(ZoneOffset.UTC).format(BER_DATETIME_FORMATTER)
            assertEquals(expectedDate, expiryDateDer.timeString)
        }

        @Test
        fun `Gateway data should be honored`() {
            val authorization = PrivateNodeRegistrationAuthorization(tomorrow, gatewayData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val actualGatewayData = ASN1OctetString.getInstance(sequence[1], false)
            assertEquals(gatewayData.asList(), actualGatewayData.octets.asList())
        }

        @Test
        fun `Signature should be valid`() {
            val authorization = PrivateNodeRegistrationAuthorization(tomorrow, gatewayData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val signature = ASN1Utils.getOctetString(sequence[2]).octets
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(
                    OIDs.PNRA,
                    ASN1Utils.derEncodeUTCDate(tomorrow),
                    DEROctetString(gatewayData)
                ),
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
                PrivateNodeRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("PNRA is not a valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least 3 items`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(DERVisibleString("a"), DERVisibleString("b")),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals(
                "PNRA plaintext should have at least 3 items (got 2)",
                exception.message
            )
        }

        @Test
        fun `Expired authorizations should be refused`() {
            val oneSecondAgo = ZonedDateTime.now().minusSeconds(1)
            val authorization = PrivateNodeRegistrationAuthorization(oneSecondAgo, gatewayData)
            val serialization = authorization.serialize(keyPair.private)

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("PNRA already expired", exception.message)
        }

        @Test
        fun `Invalid signatures should be refused`() {
            val invalidSignature = "not a valid signature".toByteArray()
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    ASN1Utils.derEncodeUTCDate(tomorrow),
                    DEROctetString(gatewayData),
                    DEROctetString(invalidSignature)
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("PNRA signature is invalid", exception.message)
        }

        @Test
        fun `Valid values should be accepted`() {
            val authorization = PrivateNodeRegistrationAuthorization(tomorrow, gatewayData)
            val serialization = authorization.serialize(keyPair.private)

            val authorizationDeserialized =
                PrivateNodeRegistrationAuthorization.deserialize(serialization, keyPair.public)

            assertEquals(tomorrow.withNano(0), authorizationDeserialized.expiryDate)
            assertEquals(gatewayData.asList(), authorizationDeserialized.gatewayData.asList())
        }
    }
}
