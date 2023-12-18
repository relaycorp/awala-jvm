package tech.relaycorp.relaynet.messages

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
import tech.relaycorp.relaynet.utils.PDACertPath

class CertificateRotationTest {
    private val certificationPath =
        CertificationPath(PDACertPath.PRIVATE_GW, listOf(PDACertPath.INTERNET_GW))

    private val formatSignature = byteArrayOf(*"Awala".toByteArray(), 0x10, 0)

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should start with format signature`() {
            val rotation = CertificateRotation(certificationPath)

            val serialization = rotation.serialize()

            assertEquals(
                formatSignature.asList(),
                serialization.slice(0..6),
            )
        }

        @Test
        fun `Serialization should contain CertificationPath`() {
            val rotation = CertificateRotation(certificationPath)

            val serialization = rotation.serialize()

            val pathSerialized = serialization.slice(7 until serialization.size)
            assertEquals(certificationPath.serialize().asList(), pathSerialized.toList())
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be long enough to potentially contain format signature`() {
            val exception =
                assertThrows<InvalidMessageException> {
                    CertificateRotation.deserialize("AwalaP".toByteArray())
                }

            assertEquals("Message is too short to contain format signature", exception.message)
        }

        @Test
        fun `Serialization should start with format signature`() {
            val exception =
                assertThrows<InvalidMessageException> {
                    CertificateRotation.deserialize("AwalaP0".toByteArray())
                }

            assertEquals("Format signature is not that of a CertificateRotation", exception.message)
        }

        @Test
        fun `Serialization should contain a CertificationPath`() {
            val serialization = CertificateRotation.FORMAT_SIGNATURE + byteArrayOf(1)

            val exception =
                assertThrows<InvalidMessageException> {
                    CertificateRotation.deserialize(serialization)
                }

            assertEquals("CertificationPath is malformed", exception.message)
            assertTrue(exception.cause is CertificationPathException)
        }

        @Test
        fun `A new instance should be returned if serialization is valid`() {
            val rotation = CertificateRotation(certificationPath)
            val serialization = rotation.serialize()

            val rotationDeserialized = CertificateRotation.deserialize(serialization)

            assertEquals(
                certificationPath.leafCertificate,
                rotationDeserialized.certificationPath.leafCertificate,
            )
            assertEquals(1, rotationDeserialized.certificationPath.certificateAuthorities.size)
            assertEquals(
                certificationPath.certificateAuthorities.first(),
                rotationDeserialized.certificationPath.certificateAuthorities.first(),
            )
        }
    }
}
