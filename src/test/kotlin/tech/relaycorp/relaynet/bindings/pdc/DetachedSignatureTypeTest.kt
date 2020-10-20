package tech.relaycorp.relaynet.bindings.pdc

import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.FullCertPath
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DetachedSignatureTypeTest {
    val signatureType = DetachedSignatureType.NONCE

    val signerPrivateKey = KeyPairSet.PRIVATE_ENDPOINT.private!!
    val signerCertificate = FullCertPath.PRIVATE_ENDPOINT
    val plaintext = "the plaintext".toByteArray()

    @Nested
    inner class Sign {
        @Test
        fun `Plaintext should not be encapsulated`() {
            val serialization = signatureType.sign(plaintext, signerPrivateKey, signerCertificate)

            val signedData = SignedData.deserialize(serialization)
            assertNull(signedData.plaintext)
        }

        @Test
        fun `Certificate should be encapsulated`() {
            val serialization = signatureType.sign(plaintext, signerPrivateKey, signerCertificate)

            val signedData = SignedData.deserialize(serialization)
            assertNotNull(signedData.signerCertificate)
            assertEquals(signerCertificate, signedData.signerCertificate)
        }

        @Test
        fun `Signature should validate`() {
            val serialization = signatureType.sign(plaintext, signerPrivateKey, signerCertificate)

            val signedData = SignedData.deserialize(serialization)
            val expectedPlaintext = ASN1Utils.serializeSequence(
                arrayOf(
                    signatureType.oid,
                    DEROctetString(plaintext)
                ),
                false
            )
            signedData.verify(expectedPlaintext)
        }
    }

    @Nested
    inner class Verify {
        @Test
        fun `SignedData value should be valid`() {
            val invalidSignedData = SignedData.sign(
                byteArrayOf(),
                KeyPairSet.PDA_GRANTEE.private, // Key doesn't correspond to certificate
                FullCertPath.PRIVATE_ENDPOINT,
                setOf(FullCertPath.PRIVATE_ENDPOINT)
            ).serialize()

            val exception = assertThrows<InvalidMessageException> {
                signatureType.verify(invalidSignedData, plaintext, listOf(FullCertPath.PRIVATE_GW))
            }

            assertEquals("SignedData value is invalid", exception.message)
            assertTrue(exception.cause is SignedDataException)
        }

        @Test
        fun `Untrusted signers should be refused`() {
            val serialization =
                signatureType.sign(plaintext, KeyPairSet.PUBLIC_GW.private, FullCertPath.PUBLIC_GW)

            val exception = assertThrows<InvalidMessageException> {
                signatureType.verify(serialization, plaintext, listOf(FullCertPath.PRIVATE_GW))
            }

            assertEquals("Signer is not trusted", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Signer certificate should be output if trusted and signature is valid`() {
            val serialization = signatureType.sign(plaintext, signerPrivateKey, signerCertificate)

            val actualSignerCertificate =
                signatureType.verify(serialization, plaintext, listOf(FullCertPath.PRIVATE_GW))

            assertEquals(signerCertificate, actualSignerCertificate)
        }
    }

    @Nested
    inner class Types {
        @Test
        fun `PARCEL_DELIVERY should use the right OID`() {
            assertEquals(
                OIDs.DETACHED_SIGNATURE.branch("0"),
                DetachedSignatureType.PARCEL_DELIVERY.oid
            )
        }

        @Test
        fun `NONCE should use the right OID`() {
            assertEquals(OIDs.DETACHED_SIGNATURE.branch("1"), DetachedSignatureType.NONCE.oid)
        }
    }
}
