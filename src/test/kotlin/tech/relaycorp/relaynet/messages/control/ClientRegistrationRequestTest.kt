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

class ClientRegistrationRequestTest {
    private val craSerialized = "CRA".toByteArray()
    private val keyPair = generateRSAKeyPair()

    @Nested
    inner class Serialize {
        @Test
        fun `Client public key should be honored`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeSequence(serialization)
            val clientPublicKeyRaw = sequence[0]
            assertEquals(
                keyPair.public.encoded.asList(),
                ASN1Utils.getOctetString(clientPublicKeyRaw).octets.asList()
            )
        }

        @Test
        fun `CRA countersignature should contain correct CRA`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeSequence(serialization)
            val craDeserialized = ASN1Utils.getOctetString(sequence[1]).octets
            assertEquals(
                craSerialized.asList(),
                craDeserialized.asList()
            )
        }

        @Test
        fun `CRA countersignature should be valid`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeSequence(serialization)
            val craCountersignatureASN1 = sequence[2]
            val craCountersignature =
                ASN1Utils.getOctetString(craCountersignatureASN1).octets
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(OIDs.CRA_COUNTERSIGNATURE, DEROctetString(craSerialized)),
                false
            )
            assertTrue(RSASigning.verify(craCountersignature, keyPair.public, expectedPlaintext))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Malformed sequence should be refused`() {
            val serialization = "invalid".toByteArray()

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationRequest.deserialize(serialization)
            }

            assertEquals("CRR is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least 3 items`() {
            val serialization =
                ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE, DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationRequest.deserialize(serialization)
            }

            assertEquals("CRR sequence should have at least 3 items (got 2)", exception.message)
        }

        @Test
        fun `Malformed client public key should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString("foo".toByteArray()),
                    DERNull.INSTANCE,
                    DERNull.INSTANCE
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationRequest.deserialize(serialization)
            }

            assertEquals("Client public key is invalid", exception.message)
            assertTrue(exception.cause is KeyException)
        }

        @Test
        fun `Invalid CRA countersignatures should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString(keyPair.public.encoded),
                    DEROctetString(craSerialized),
                    DEROctetString(RSASigning.sign("foo".toByteArray(), keyPair.private))
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationRequest.deserialize(serialization)
            }

            assertEquals("CRA countersignature is invalid", exception.message)
        }

        @Test
        fun `Valid values should be accepted`() {
            val crr = ClientRegistrationRequest(keyPair.public, craSerialized)
            val serialization = crr.serialize(keyPair.private)

            val crrDeserialized = ClientRegistrationRequest.deserialize(serialization)

            assertEquals(
                crr.clientPublicKey.encoded.asList(),
                crrDeserialized.clientPublicKey.encoded.asList()
            )
            assertEquals(crr.craSerialized.asList(), crrDeserialized.craSerialized.asList())
        }
    }
}
