package tech.relaycorp.relaynet.messages.control

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.RAMFStubs
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class PrivateNodeRegistrationTest {
    private val gatewayInternetAddress = RAMFStubs.RECIPIENT_INTERNET_ADDRESS
    private val gatewaySessionKey = (SessionKeyPair.generate()).sessionKey

    @Nested
    inner class Serialize {
        @Test
        fun `Node certificate should be serialized`() {
            val registration =
                PrivateNodeRegistration(
                    PDACertPath.PRIVATE_ENDPOINT,
                    PDACertPath.PRIVATE_GW,
                    gatewayInternetAddress,
                )

            val serialization = registration.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val nodeCertificateASN1 = ASN1Utils.getOctetString(sequence.first())
            assertEquals(
                PDACertPath.PRIVATE_ENDPOINT.serialize().asList(),
                nodeCertificateASN1.octets.asList(),
            )
        }

        @Test
        fun `Gateway certificate should be serialized`() {
            val registration =
                PrivateNodeRegistration(
                    PDACertPath.PRIVATE_ENDPOINT,
                    PDACertPath.PRIVATE_GW,
                    gatewayInternetAddress,
                )

            val serialization = registration.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val gatewayCertificateASN1 = ASN1Utils.getOctetString(sequence[1])
            assertEquals(
                PDACertPath.PRIVATE_GW.serialize().asList(),
                gatewayCertificateASN1.octets.asList(),
            )
        }

        @Test
        fun `Gateway Internet address should be serialized`() {
            val registration =
                PrivateNodeRegistration(
                    PDACertPath.PRIVATE_ENDPOINT,
                    PDACertPath.PRIVATE_GW,
                    gatewayInternetAddress,
                )

            val serialization = registration.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val gatewayInternetAddressASN1 = ASN1Utils.getVisibleString(sequence[2])
            assertEquals(gatewayInternetAddress, gatewayInternetAddressASN1.string)
        }

        @Nested
        inner class GatewaySessionKey {
            @Test
            fun `Session key should be absent from serialization if it does not exist`() {
                val registration =
                    PrivateNodeRegistration(
                        PDACertPath.PRIVATE_ENDPOINT,
                        PDACertPath.PRIVATE_GW,
                        gatewayInternetAddress,
                    )

                val serialization = registration.serialize()

                val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
                assertEquals(3, sequence.size)
            }

            @Test
            fun `Key id should be serialized`() {
                val registration =
                    PrivateNodeRegistration(
                        PDACertPath.PRIVATE_ENDPOINT,
                        PDACertPath.PRIVATE_GW,
                        gatewayInternetAddress,
                        gatewaySessionKey,
                    )

                val serialization = registration.serialize()

                val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
                val sessionKeyASN1 = ASN1Sequence.getInstance(sequence[3], false)
                val keyIdASN1 =
                    ASN1Utils.getOctetString(sessionKeyASN1.getObjectAt(0) as ASN1TaggedObject)
                assertEquals(gatewaySessionKey.keyId.asList(), keyIdASN1.octets.asList())
            }

            @Test
            fun `Public key should be serialized`() {
                val registration =
                    PrivateNodeRegistration(
                        PDACertPath.PRIVATE_ENDPOINT,
                        PDACertPath.PRIVATE_GW,
                        gatewayInternetAddress,
                        gatewaySessionKey,
                    )

                val serialization = registration.serialize()

                val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
                val sessionKeyASN1 = ASN1Sequence.getInstance(sequence[3], false)
                val sessionPublicKeyASN1 =
                    ASN1Utils.getOctetString(sessionKeyASN1.getObjectAt(1) as ASN1TaggedObject)
                assertEquals(
                    gatewaySessionKey.publicKey.encoded.asList(),
                    sessionPublicKeyASN1.octets.asList(),
                )
            }
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be DER sequence`() {
            val invalidSerialization = "foo".toByteArray()

            val exception =
                assertThrows<InvalidMessageException> {
                    PrivateNodeRegistration.deserialize(invalidSerialization)
                }

            assertEquals("Node registration is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least three items`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(listOf(DERNull.INSTANCE, DERNull.INSTANCE), false)

            val exception =
                assertThrows<InvalidMessageException> {
                    PrivateNodeRegistration.deserialize(invalidSerialization)
                }

            assertEquals(
                "Node registration sequence should have at least three items (got 2)",
                exception.message,
            )
        }

        @Test
        fun `Invalid node certificates should be refused`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(
                    listOf(
                        DERNull.INSTANCE,
                        DERNull.INSTANCE,
                        DERNull.INSTANCE,
                    ),
                    false,
                )

            val exception =
                assertThrows<InvalidMessageException> {
                    PrivateNodeRegistration.deserialize(invalidSerialization)
                }

            assertEquals(
                "Node registration contains invalid node certificate",
                exception.message,
            )
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Invalid gateway certificates should be refused`() {
            val invalidSerialization =
                ASN1Utils.serializeSequence(
                    listOf(
                        DEROctetString(PDACertPath.PRIVATE_ENDPOINT.serialize()),
                        DERNull.INSTANCE,
                        DERNull.INSTANCE,
                    ),
                    false,
                )

            val exception =
                assertThrows<InvalidMessageException> {
                    PrivateNodeRegistration.deserialize(invalidSerialization)
                }

            assertEquals(
                "Node registration contains invalid gateway certificate",
                exception.message,
            )
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Malformed Internet address for gateway should be refused`() {
            val malformedDomainName = "not a domain name"
            val invalidRegistration =
                PrivateNodeRegistration(
                    PDACertPath.PRIVATE_ENDPOINT,
                    PDACertPath.PRIVATE_GW,
                    malformedDomainName,
                )
            val invalidSerialization = invalidRegistration.serialize()

            val exception =
                assertThrows<InvalidMessageException> {
                    PrivateNodeRegistration.deserialize(invalidSerialization)
                }

            assertEquals(
                "Malformed gateway Internet address ($malformedDomainName)",
                exception.message,
            )
        }

        @Test
        fun `Valid registration without session key should be accepted`() {
            val registration =
                PrivateNodeRegistration(
                    PDACertPath.PRIVATE_ENDPOINT,
                    PDACertPath.PRIVATE_GW,
                    gatewayInternetAddress,
                )
            val serialization = registration.serialize()

            val registrationDeserialized = PrivateNodeRegistration.deserialize(serialization)

            assertEquals(
                PDACertPath.PRIVATE_ENDPOINT,
                registrationDeserialized.privateNodeCertificate,
            )
            assertEquals(
                PDACertPath.PRIVATE_GW,
                registrationDeserialized.gatewayCertificate,
            )
            assertEquals(gatewayInternetAddress, registrationDeserialized.gatewayInternetAddress)
            assertNull(registrationDeserialized.gatewaySessionKey)
        }

        @Nested
        inner class GatewaySessionKey {
            @Test
            fun `SEQUENCE should contain at least two items`() {
                val invalidSerialization =
                    ASN1Utils.serializeSequence(
                        listOf(
                            DEROctetString(PDACertPath.PRIVATE_ENDPOINT.serialize()),
                            DEROctetString(PDACertPath.PRIVATE_GW.serialize()),
                            DERVisibleString(gatewayInternetAddress),
                            ASN1Utils.makeSequence(listOf(DEROctetString(gatewaySessionKey.keyId))),
                        ),
                        false,
                    )

                val exception =
                    assertThrows<InvalidMessageException> {
                        PrivateNodeRegistration.deserialize(invalidSerialization)
                    }

                assertEquals(
                    "Session key SEQUENCE should have at least 2 items (got 1)",
                    exception.message,
                )
            }

            @Test
            fun `Session key should be a valid ECDH public key`() {
                val invalidRegistration =
                    PrivateNodeRegistration(
                        PDACertPath.PRIVATE_ENDPOINT,
                        PDACertPath.PRIVATE_GW,
                        gatewayInternetAddress,
                        SessionKey(
                            gatewaySessionKey.keyId,
                            // Invalid: Not an ECDH key
                            KeyPairSet.PRIVATE_ENDPOINT.public,
                        ),
                    )
                val invalidSerialization = invalidRegistration.serialize()

                val exception =
                    assertThrows<InvalidMessageException> {
                        PrivateNodeRegistration.deserialize(invalidSerialization)
                    }

                assertEquals(
                    "Session key is not a valid ECDH public key",
                    exception.message,
                )
                assertTrue(exception.cause is KeyException)
            }

            @Test
            fun `Valid registration with session key should be accepted`() {
                val registration =
                    PrivateNodeRegistration(
                        PDACertPath.PRIVATE_ENDPOINT,
                        PDACertPath.PRIVATE_GW,
                        gatewayInternetAddress,
                        gatewaySessionKey,
                    )
                val serialization = registration.serialize()

                val registrationDeserialized = PrivateNodeRegistration.deserialize(serialization)

                assertEquals(
                    gatewaySessionKey,
                    registrationDeserialized.gatewaySessionKey,
                )
            }
        }
    }
}
