package tech.relaycorp.relaynet.pki

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.Certificate as BCCertificate
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.toExplicitlyTaggedObject
import tech.relaycorp.relaynet.utils.toImplicitlyTaggedObject
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CertificationPathTest {
    @Nested
    inner class Serialize {
        @Test
        fun `Leaf certificate should be serialized`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))

            val serialization = path.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val leafCertificate = BCCertificate.getInstance(sequence.first(), false)
            assertEquals(PDACertPath.PDA.certificateHolder.toASN1Structure(), leafCertificate)
        }

        @Test
        fun `Chain should be serialized`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))

            val serialization = path.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val chainSequence = ASN1Sequence.getInstance(sequence[1], false)
            assertEquals(1, chainSequence.size())
            val caSerialized = (chainSequence.first() as DEROctetString).octets
            val ca = Certificate.deserialize(caSerialized)
            assertEquals(PDACertPath.PRIVATE_ENDPOINT, ca)
        }
    }

    @Nested
    inner class Decode {
        @Test
        fun `Encoding should be a sequence`() {
            val encoding = DERNull.INSTANCE.toImplicitlyTaggedObject()

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.decode(encoding)
            }

            assertEquals("Serialisation is not an implicitly-tagged sequence", exception.message)
        }

        @Test
        fun `Encoding should be implicitly tagged`() {
            val encoding = ASN1Utils.makeSequence(emptyList()).toExplicitlyTaggedObject()

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.decode(encoding)
            }

            assertEquals("Serialisation is not an implicitly-tagged sequence", exception.message)
        }

        @Test
        fun `Valid path should be output`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))
            val encoding = path.encode()

            val pathDecoded = CertificationPath.decode(encoding.toImplicitlyTaggedObject())

            assertEquals(PDACertPath.PDA, pathDecoded.leafCertificate)
            assertEquals(
                listOf(PDACertPath.PRIVATE_ENDPOINT),
                pathDecoded.certificateAuthorities,
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Malformed sequence should be refused`() {
            val serialization = "invalid".toByteArray()

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Path is not a valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least two items`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(DEROctetString(PDACertPath.PDA.serialize())), false
            )

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Path sequence should have at least 2 items", exception.message)
        }

        @Test
        fun `Malformed leaf certificate should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    DEROctetString("malformed".toByteArray()),
                    ASN1Utils.makeSequence(emptyList()),
                ),
                false
            )

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Leaf certificate is malformed", exception.message)
            assertTrue(exception.cause is IllegalStateException)
        }

        @Test
        fun `Malformed chain should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    PDACertPath.PDA.certificateHolder.toASN1Structure(),
                    DERNull.INSTANCE,
                ),
                false
            )

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Chain is malformed", exception.message)
            assertTrue(exception.cause is IllegalStateException)
        }

        @Test
        fun `Malformed certificate in chain should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    PDACertPath.PDA.certificateHolder.toASN1Structure(),
                    ASN1Utils.makeSequence(listOf(DEROctetString("malformed".toByteArray()))),
                ),
                false
            )

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Chain contains malformed certificate", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Malformed OCTET STRING in chain should be refused`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    PDACertPath.PDA.certificateHolder.toASN1Structure(),
                    ASN1Utils.makeSequence(listOf(DERNull.INSTANCE)),
                ),
                false
            )

            val exception = assertThrows<CertificationPathException> {
                CertificationPath.deserialize(serialization)
            }

            assertEquals("Chain contains non-OCTET STRING item", exception.message)
            assertTrue(exception.cause is IllegalArgumentException)
        }

        @Test
        fun `Valid serialization should be accepted`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))
            val serialization = path.serialize()

            val pathDeserialized = CertificationPath.deserialize(serialization)

            assertEquals(PDACertPath.PDA, pathDeserialized.leafCertificate)
            assertEquals(
                listOf(PDACertPath.PRIVATE_ENDPOINT),
                pathDeserialized.certificateAuthorities,
            )
        }
    }

    @Nested
    inner class Validate {
        @Test
        fun `Validation should fail if there are no CAs`() {
            val path = CertificationPath(PDACertPath.PDA, emptyList())

            val exception = assertThrows<CertificationPathException> {
                path.validate()
            }

            assertEquals("There are no CAs", exception.message)
        }

        @Test
        fun `Validation should fail if there is no path from root to leaf certificate`() {
            val path = CertificationPath(
                PDACertPath.PDA,
                listOf(PDACertPath.PRIVATE_GW), // Intermediate certificate is missing
            )

            val exception = assertThrows<CertificationPathException> {
                path.validate()
            }

            assertEquals("Certification path is invalid", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Validation should succeed if there is a path from root to leaf certificate`() {
            val path = CertificationPath(
                PDACertPath.PDA,
                listOf(PDACertPath.PRIVATE_ENDPOINT, PDACertPath.PRIVATE_GW)
            )

            path.validate()
        }

        @Test
        fun `Validation should succeed if there is the root issued the leaf directly`() {
            val path = CertificationPath(
                PDACertPath.PDA,
                listOf(PDACertPath.PRIVATE_ENDPOINT)
            )

            path.validate()
        }
    }
}
