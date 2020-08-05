package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.BER_DATETIME_FORMATTER
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ClientRegistrationAuthorizationTest {
    private val tomorrow = ZonedDateTime.now().plusDays(1)
    private val serverData = "this is opaque to the client".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Serialize {
        @Test
        fun `SignedData value should be valid`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            SignedData.deserialize(serialization)
                .also { it.verify(signerPublicKey = keyPair.public) }
        }

        @Test
        fun `SignedData value should encapsulate authorization data`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val signedData = SignedData.deserialize(serialization)
            assertNotNull(signedData.plaintext)
            ASN1Utils.deserializeSequence(signedData.plaintext!!)
        }

        @Test
        fun `The right OID should be used`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = extractSequence(serialization)
            val oidRaw = sequence.first() as ASN1TaggedObject
            assertEquals(
                OIDs.CLIENT_REGISTRATION_AUTHZ,
                ASN1ObjectIdentifier.getInstance(oidRaw, false)
            )
        }

        @Test
        fun `Expiry date should be honored`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = extractSequence(serialization)
            val expiryDateRaw = sequence[1] as ASN1TaggedObject
            val expiryDateDer = DERGeneralizedTime.getInstance(expiryDateRaw, false)
            val expectedDate =
                tomorrow.withZoneSameInstant(ZoneOffset.UTC).format(BER_DATETIME_FORMATTER)
            assertEquals(expectedDate, expiryDateDer.timeString)
        }

        @Test
        fun `Server data should be honored`() {
            val authorization = ClientRegistrationAuthorization(tomorrow, serverData)

            val serialization = authorization.serialize(keyPair.private)

            val sequence = extractSequence(serialization)
            val actualServerData =
                ASN1OctetString.getInstance(sequence.last() as ASN1TaggedObject, false)
            assertEquals(serverData.asList(), actualServerData.octets.asList())
        }

        private fun extractSequence(serialization: ByteArray): Array<ASN1Encodable> {
            val signedData = SignedData.deserialize(serialization)
            return ASN1Utils.deserializeSequence(signedData.plaintext!!)
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

            assertEquals("Serialization is not a valid SignedData value", exception.message)
            assertTrue(exception.cause is SignedDataException)
        }

        @Test
        fun `Invalid signatures should be refused`() {
            val anotherKeyPair = generateRSAKeyPair()
            val serialization =
                SignedData.sign("f".toByteArray(), anotherKeyPair.private).serialize()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals("Serialization is not a valid SignedData value", exception.message)
            assertTrue(exception.cause is SignedDataException)
        }

        @Test
        fun `Plaintext should be a DER sequence`() {
            val serialization =
                SignedData.sign(DERNull.INSTANCE.encoded, keyPair.private).serialize()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals(
                "CRA plaintext should be a DER sequence",
                exception.message
            )
        }

        @Test
        fun `Sequence should have at least 3 items`() {
            val plaintext = ASN1Utils.serializeSequence(
                arrayOf(DERVisibleString("a"), DERVisibleString("b")),
                false
            )
            val serialization = SignedData.sign(plaintext, keyPair.private).serialize()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals(
                "CRA plaintext should have at least 3 items (got 2)",
                exception.message
            )
        }

        @Test
        fun `Invalid OIDs should be refused`() {
            val invalidOID = ASN1ObjectIdentifier("1.2.3")
            val plaintext = ASN1Utils.serializeSequence(
                arrayOf(invalidOID, DERVisibleString("a"), DERVisibleString("b")),
                false
            )
            val serialization = SignedData.sign(plaintext, keyPair.private).serialize()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationAuthorization.deserialize(serialization, keyPair.public)
            }

            assertEquals(
                "CRA plaintext has invalid OID (got ${invalidOID.id})",
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
