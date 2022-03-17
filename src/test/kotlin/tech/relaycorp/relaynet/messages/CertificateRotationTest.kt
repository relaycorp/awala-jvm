package tech.relaycorp.relaynet.messages

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CertificateRotationTest {
    private val subjectCertificate = PDACertPath.PRIVATE_GW
    private val issuerCertificate = PDACertPath.PUBLIC_GW

    private val formatSignature = byteArrayOf(*"Relaynet".toByteArray(), 0x10, 0)

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should start with format signature`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            assertEquals(
                formatSignature.asList(), serialization.slice(0..9)
            )
        }

        @Test
        fun `Serialization should contain a 2-item sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            assertEquals(2, sequenceItems.size)
        }

        @Test
        fun `Subject certificate should be in sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            val certificateSerialized = ASN1Utils.getOctetString(sequenceItems.first()).octets
            assertEquals(subjectCertificate, Certificate.deserialize(certificateSerialized))
        }

        @Test
        fun `Chain certificates should be in sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            val chainSequence = ASN1Sequence.getInstance(sequenceItems[1], false)
            assertEquals(1, chainSequence.size())
            val issuerSerialized =
                DEROctetString.getInstance(chainSequence.first()).octets
            assertEquals(issuerCertificate, Certificate.deserialize(issuerSerialized))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be long enough to potentially contain format signature`() {
            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize("RelaynetP".toByteArray())
            }

            assertEquals("Message is too short to contain format signature", exception.message)
        }

        @Test
        fun `Serialization should start with format signature`() {
            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize("RelaynetP0".toByteArray())
            }

            assertEquals("Format signature is not that of a CertificateRotation", exception.message)
        }

        @Test
        fun `Serialization should contain a DER sequence`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + byteArrayOf(1)

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Serialization does not contain valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Serialization should contain a sequence of a least 2 items`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + ASN1Utils.serializeSequence(
                listOf(DERVisibleString("the subject cert")), false
            )

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Sequence should contain at least 2 items", exception.message)
        }

        @Test
        fun `Malformed subject certificate should be refused`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + ASN1Utils.serializeSequence(
                listOf(
                    DERVisibleString("malformed"), ASN1Utils.makeSequence(emptyList(), false)
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Subject certificate is malformed", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Malformed chain should be refused`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + ASN1Utils.serializeSequence(
                listOf(
                    DEROctetString(subjectCertificate.serialize()), DERVisibleString("malformed")
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Chain is malformed", exception.message)
            assertTrue(exception.cause is IllegalArgumentException)
        }

        @Test
        fun `Malformed chain certificate should be refused`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + ASN1Utils.serializeSequence(
                listOf(
                    DEROctetString(subjectCertificate.serialize()),
                    ASN1Utils.makeSequence(
                        listOf(DEROctetString("malformed".toByteArray()))
                    )
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Chain contains malformed certificate", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Chain certificates should be OCTET STRINGs`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + ASN1Utils.serializeSequence(
                listOf(
                    DEROctetString(subjectCertificate.serialize()),
                    ASN1Utils.makeSequence(
                        listOf(DERVisibleString("malformed"))
                    )
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                CertificateRotation.deserialize(serialization)
            }

            assertEquals("Chain contains malformed certificate", exception.message)
            assertTrue(exception.cause is IllegalArgumentException)
        }

        @Test
        fun `A new instance should be returned if serialization is valid`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))
            val serialization = rotation.serialize()

            val rotationDeserialized = CertificateRotation.deserialize(serialization)

            assertEquals(subjectCertificate, rotationDeserialized.subjectCertificate)
            assertEquals(1, rotationDeserialized.chain.size)
            assertEquals(issuerCertificate, rotationDeserialized.chain.first())
        }

        @Test
        fun `Chain should be empty if sub-sequence is empty`() {
            val rotation = CertificateRotation(subjectCertificate, emptyList())
            val serialization = rotation.serialize()

            val rotationDeserialized = CertificateRotation.deserialize(serialization)

            assertEquals(0, rotationDeserialized.chain.size)
        }
    }
}
