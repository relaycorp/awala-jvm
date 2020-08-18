package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.FullCertPath
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NonceSignatureTest {
    val signerPrivateKey = KeyPairSet.PRIVATE_ENDPOINT.private!!
    val signerCertificate = FullCertPath.PRIVATE_ENDPOINT

    val nonce = "the nonce".toByteArray()

    @Nested
    inner class Serialize {
        @Test
        fun `SignedData value should verify with the encapsulated data and certificate`() {
            val signature = NonceSignature(nonce, signerCertificate)

            val serialization = signature.serialize(signerPrivateKey)

            SignedData.deserialize(serialization).verify()
        }

        @Test
        fun `Plaintext should be DER sequence`() {
            val signature = NonceSignature(nonce, signerCertificate)

            val serialization = signature.serialize(signerPrivateKey)

            val signedData = SignedData.deserialize(serialization)
            assertNotNull(signedData.plaintext)
            ASN1Utils.deserializeSequence(signedData.plaintext!!)
        }

        @Test
        fun `Plaintext OID should match expected id`() {
            val signature = NonceSignature(nonce, signerCertificate)

            val serialization = signature.serialize(signerPrivateKey)

            val signedData = SignedData.deserialize(serialization)
            val plaintextSequence = ASN1Utils.deserializeSequence(signedData.plaintext!!)
            val oid = ASN1Utils.getOID(plaintextSequence.first())
            assertEquals(OIDs.NONCE_SIGNATURE, oid)
        }

        @Test
        fun `Nonce signature should be honored`() {
            val signature = NonceSignature(nonce, signerCertificate)

            val serialization = signature.serialize(signerPrivateKey)

            val signedData = SignedData.deserialize(serialization)
            val plaintextSequence = ASN1Utils.deserializeSequence(signedData.plaintext!!)
            val nonceASN1 = ASN1Utils.getOctetString(plaintextSequence[1])
            assertEquals(nonce.asList(), nonceASN1.octets.asList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `SignedData value should be valid`() {
            val invalidSignedData = SignedData.sign(
                byteArrayOf(),
                KeyPairSet.PDA_GRANTEE.private, // Key doesn't correspond to certificate
                FullCertPath.PRIVATE_ENDPOINT,
                setOf(FullCertPath.PRIVATE_ENDPOINT)
            ).serialize()

            val exception = assertThrows<InvalidMessageException> {
                NonceSignature.deserialize(invalidSignedData)
            }

            assertEquals("SignedData value is invalid", exception.message)
            assertTrue(exception.cause is SignedDataException)
        }

        @Test
        fun `Plaintext should be DER sequence`() {
            val signedData = SignedData.sign(
                DERNull.INSTANCE.encoded,
                KeyPairSet.PRIVATE_ENDPOINT.private,
                FullCertPath.PRIVATE_ENDPOINT,
                setOf(FullCertPath.PRIVATE_ENDPOINT)
            ).serialize()

            val exception = assertThrows<InvalidMessageException> {
                NonceSignature.deserialize(signedData)
            }

            assertEquals("Signature plaintext is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Plaintext sequence should have at least two items`() {
            val plaintext = ASN1Utils.serializeSequence(arrayOf(DERNull.INSTANCE), false)
            val signedData = SignedData.sign(
                plaintext,
                KeyPairSet.PRIVATE_ENDPOINT.private,
                FullCertPath.PRIVATE_ENDPOINT,
                setOf(FullCertPath.PRIVATE_ENDPOINT)
            ).serialize()

            val exception = assertThrows<InvalidMessageException> {
                NonceSignature.deserialize(signedData)
            }

            assertEquals(
                "Signature sequence should have at least 2 items (got 1)",
                exception.message
            )
        }

        @Test
        fun `Plaintext OID should match the expected id`() {
            val invalidOID = ASN1ObjectIdentifier("1.2.3.4")
            val plaintext =
                ASN1Utils.serializeSequence(arrayOf(invalidOID, DERNull.INSTANCE), false)
            val signedData = SignedData.sign(
                plaintext,
                KeyPairSet.PRIVATE_ENDPOINT.private,
                FullCertPath.PRIVATE_ENDPOINT,
                setOf(FullCertPath.PRIVATE_ENDPOINT)
            ).serialize()

            val exception = assertThrows<InvalidMessageException> {
                NonceSignature.deserialize(signedData)
            }

            assertEquals("Signature OID is invalid (got ${invalidOID.id})", exception.message)
        }

        @Test
        fun `Signature should be output if its serialization is valid`() {
            val signature = NonceSignature(nonce, signerCertificate)
            val serialization = signature.serialize(signerPrivateKey)

            val signatureDeserialized = NonceSignature.deserialize(serialization)

            assertEquals(nonce.asList(), signatureDeserialized.nonce.asList())
            assertEquals(signerCertificate, signatureDeserialized.signerCertificate)
        }
    }
}
