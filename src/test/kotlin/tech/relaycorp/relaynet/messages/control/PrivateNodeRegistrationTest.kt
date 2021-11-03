package tech.relaycorp.relaynet.messages.control

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class PrivateNodeRegistrationTest {
    @Nested
    inner class Serialize {
        @Test
        fun `Node certificate should be serialized`() {
            val registration =
                PrivateNodeRegistration(PDACertPath.PRIVATE_ENDPOINT, PDACertPath.PRIVATE_GW)

            val serialization = registration.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val nodeCertificateASN1 = ASN1Utils.getOctetString(sequence.first())
            assertEquals(
                PDACertPath.PRIVATE_ENDPOINT.serialize().asList(),
                nodeCertificateASN1.octets.asList()
            )
        }

        @Test
        fun `Gateway certificate should be serialized`() {
            val registration =
                PrivateNodeRegistration(PDACertPath.PRIVATE_ENDPOINT, PDACertPath.PRIVATE_GW)

            val serialization = registration.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val gatewayCertificateASN1 = ASN1Utils.getOctetString(sequence[1])
            assertEquals(
                PDACertPath.PRIVATE_GW.serialize().asList(),
                gatewayCertificateASN1.octets.asList()
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be DER sequence`() {
            val invalidSerialization = "foo".toByteArray()

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistration.deserialize(invalidSerialization)
            }

            assertEquals("Node registration is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least two items`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(listOf(DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistration.deserialize(invalidSerialization)
            }

            assertEquals(
                "Node registration sequence should have at least two items (got 1)",
                exception.message
            )
        }

        @Test
        fun `Invalid node certificates should be refused`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(listOf(DERNull.INSTANCE, DERNull.INSTANCE), false)

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistration.deserialize(invalidSerialization)
            }

            assertEquals(
                "Node registration contains invalid node certificate",
                exception.message
            )
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Invalid gateway certificates should be refused`() {
            val invalidSerialization = ASN1Utils.serializeSequence(
                listOf(
                    DEROctetString(PDACertPath.PRIVATE_ENDPOINT.serialize()),
                    DERNull.INSTANCE
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                PrivateNodeRegistration.deserialize(invalidSerialization)
            }

            assertEquals(
                "Node registration contains invalid gateway certificate",
                exception.message
            )
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Valid registration should be accepted`() {
            val registration =
                PrivateNodeRegistration(PDACertPath.PRIVATE_ENDPOINT, PDACertPath.PRIVATE_GW)
            val serialization = registration.serialize()

            val registrationDeserialized = PrivateNodeRegistration.deserialize(serialization)

            assertEquals(
                PDACertPath.PRIVATE_ENDPOINT,
                registrationDeserialized.privateNodeCertificate
            )
            assertEquals(
                PDACertPath.PRIVATE_GW,
                registrationDeserialized.gatewayCertificate
            )
        }
    }
}
