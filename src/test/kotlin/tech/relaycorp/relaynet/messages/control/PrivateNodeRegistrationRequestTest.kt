package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.RSASigning
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PrivateNodeRegistrationRequestTest {
    private val pnraSerialized = "PNRA".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Serialize {
        @Test
        fun `Private node public key should be honored`() {
            val request = PrivateNodeRegistrationRequest(keyPair.public, pnraSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val privateNodePublicKeyRaw = sequence[0]
            assertEquals(
                keyPair.public.encoded.asList(),
                ASN1Utils.getOctetString(privateNodePublicKeyRaw).octets.asList()
            )
        }

        @Test
        fun `PNRA countersignature should contain correct PNRA`() {
            val request = PrivateNodeRegistrationRequest(keyPair.public, pnraSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val pnraDeserialized = ASN1Utils.getOctetString(sequence[1]).octets
            assertEquals(
                pnraSerialized.asList(),
                pnraDeserialized.asList()
            )
        }

        @Test
        fun `PNRA countersignature should be valid`() {
            val request = PrivateNodeRegistrationRequest(keyPair.public, pnraSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val pnraCountersignatureASN1 = sequence[2]
            val pnraCountersignature =
                ASN1Utils.getOctetString(pnraCountersignatureASN1).octets
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(OIDs.PNRA_COUNTERSIGNATURE, DEROctetString(pnraSerialized)),
                false
            )
            assertTrue(RSASigning.verify(pnraCountersignature, keyPair.public, expectedPlaintext))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Malformed sequence should be refused`() {
            val serialization = "invalid".toByteArray()

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationRequest.deserialize(serialization)
            }

            assertEquals("PNRR is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least 3 items`() {
            val serialization =
                ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE, DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationRequest.deserialize(serialization)
            }

            assertEquals("PNRR sequence should have at least 3 items (got 2)", exception.message)
        }

        @Test
        fun `Malformed private node public key should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString("foo".toByteArray()),
                    DERNull.INSTANCE,
                    DERNull.INSTANCE
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationRequest.deserialize(serialization)
            }

            assertEquals("Private node public key is invalid", exception.message)
            assertTrue(exception.cause is KeyException)
        }

        @Test
        fun `Invalid PNRA countersignatures should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString(keyPair.public.encoded),
                    DEROctetString(pnraSerialized),
                    DEROctetString(RSASigning.sign("foo".toByteArray(), keyPair.private))
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistrationRequest.deserialize(serialization)
            }

            assertEquals("PNRA countersignature is invalid", exception.message)
        }

        @Test
        fun `Valid values should be accepted`() {
            val crr = PrivateNodeRegistrationRequest(keyPair.public, pnraSerialized)
            val serialization = crr.serialize(keyPair.private)

            val crrDeserialized = PrivateNodeRegistrationRequest.deserialize(serialization)

            assertEquals(
                crr.privateNodePublicKey.encoded.asList(),
                crrDeserialized.privateNodePublicKey.encoded.asList()
            )
            assertEquals(crr.pnraSerialized.asList(), crrDeserialized.pnraSerialized.asList())
        }
    }
}
