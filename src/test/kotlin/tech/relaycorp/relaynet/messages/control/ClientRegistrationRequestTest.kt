package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
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
        fun `CRA countersignature should be a valid SignedData value`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeSequence(serialization)
            val craCountersignatureASN1 = sequence[1]
            val craCountersignatureSerialized =
                ASN1Utils.getOctetString(craCountersignatureASN1).octets
            SignedData.deserialize(craCountersignatureSerialized)
                .also { it.verify(signerPublicKey = keyPair.public) }
        }

        @Test
        fun `CRA countersignature should be prefixed with correct OID`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val requestSequence = ASN1Utils.deserializeSequence(serialization)
            val craCountersignatureASN1 = requestSequence[1]
            val craCountersignature = ASN1Utils.getOctetString(craCountersignatureASN1)
            val craSequence = extractSignedSequence(craCountersignature.octets)
            assertEquals(
                OIDs.CRA_COUNTERSIGNATURE,
                ASN1Utils.getOID(craSequence.first())
            )
        }

        @Test
        fun `CRA countersignature should contain correct CRA`() {
            val request = ClientRegistrationRequest(keyPair.public, craSerialized)

            val serialization = request.serialize(keyPair.private)

            val sequence = ASN1Utils.deserializeSequence(serialization)
            val signedCRA = ASN1Utils.getOctetString(sequence[1])
            val craSequence = extractSignedSequence(signedCRA.octets)
            val authorizationASN1 = craSequence[1]
            assertEquals(
                craSerialized.asList(),
                ASN1Utils.getOctetString(authorizationASN1).octets.asList()
            )
        }

        private fun extractSignedSequence(serialization: ByteArray): Array<ASN1TaggedObject> {
            val signedData = SignedData.deserialize(serialization)
            return ASN1Utils.deserializeSequence(signedData.plaintext!!)
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
        fun `Sequence should have at least 2 items`() {
            val serialization = ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                ClientRegistrationRequest.deserialize(serialization)
            }

            assertEquals("CRR sequence should have at least 2 items (got 1)", exception.message)
        }

        @Test
        fun `Malformed client public key should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                arrayOf(
                    DEROctetString("foo".toByteArray()),
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

        @Nested
        inner class CRACountersignature {
            @Test
            fun `Malformed values should be refused`() {
                val serialization = ASN1Utils.serializeSequence(
                    arrayOf(
                        DEROctetString(keyPair.public.encoded),
                        DEROctetString("not a SignedData value".toByteArray())
                    ),
                    false
                )

                val exception = assertThrows<InvalidMessageException> {
                    ClientRegistrationRequest.deserialize(serialization)
                }

                assertEquals(
                    "CRA countersignature is not a valid SignedData value",
                    exception.message
                )
                assertTrue(exception.cause is SignedDataException)
            }

            @Test
            fun `Encapsulated public key should correspond to countersignature private key`() {
                val anotherKeyPair = generateRSAKeyPair()
                val invalidCRASerialized =
                    SignedData.sign("f".toByteArray(), anotherKeyPair.private).serialize()
                val serialization = ASN1Utils.serializeSequence(
                    arrayOf(
                        DEROctetString(keyPair.public.encoded),
                        DEROctetString(invalidCRASerialized)
                    ),
                    false
                )

                val exception = assertThrows<InvalidMessageException> {
                    ClientRegistrationRequest.deserialize(serialization)
                }

                assertEquals(
                    "CRA countersignature is not a valid SignedData value",
                    exception.message
                )
                assertTrue(exception.cause is SignedDataException)
            }

            @Test
            fun `Plaintext should be a DER sequence`() {
                val invalidCRACountersignature =
                    SignedData.sign(DERNull.INSTANCE.encoded, keyPair.private)
                val serialization = ASN1Utils.serializeSequence(
                    arrayOf(
                        DEROctetString(keyPair.public.encoded),
                        DEROctetString(invalidCRACountersignature.serialize())
                    ),
                    false
                )

                val exception = assertThrows<InvalidMessageException> {
                    ClientRegistrationRequest.deserialize(serialization)
                }

                assertEquals(
                    "CRA countersignature plaintext should be a DER sequence",
                    exception.message
                )
                assertTrue(exception.cause is ASN1Exception)
            }

            @Test
            fun `Sequence should have at least 2 items`() {
                val invalidCRACountersignaturePlaintext =
                    ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE), false)
                val invalidCRACountersignature =
                    SignedData.sign(invalidCRACountersignaturePlaintext, keyPair.private)
                val serialization = ASN1Utils.serializeSequence(
                    arrayOf(
                        DEROctetString(keyPair.public.encoded),
                        DEROctetString(invalidCRACountersignature.serialize())
                    ),
                    false
                )

                val exception = assertThrows<InvalidMessageException> {
                    ClientRegistrationRequest.deserialize(serialization)
                }

                assertEquals(
                    "CRA countersignature sequence should have at least 2 items (got 1)",
                    exception.message
                )
            }

            @Test
            fun `Invalid OIDs should be refused`() {
                val invalidOID = ASN1ObjectIdentifier("1.2.3")
                val invalidCRACountersignaturePlaintext = ASN1Utils.serializeSequence(
                    arrayOf(invalidOID, DERNull.INSTANCE, DERNull.INSTANCE),
                    false
                )
                val invalidCRACountersignature =
                    SignedData.sign(invalidCRACountersignaturePlaintext, keyPair.private)
                val serialization = ASN1Utils.serializeSequence(
                    arrayOf(
                        DEROctetString(keyPair.public.encoded),
                        DEROctetString(invalidCRACountersignature.serialize())
                    ),
                    false
                )

                val exception = assertThrows<InvalidMessageException> {
                    ClientRegistrationRequest.deserialize(serialization)
                }

                assertEquals(
                    "CRA countersignature has invalid OID (got ${invalidOID.id})",
                    exception.message
                )
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
}
