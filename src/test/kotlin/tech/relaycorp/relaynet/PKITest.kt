package tech.relaycorp.relaynet

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PKITest {
    val identityKeyPair = KeyPairSet.PUBLIC_GW
    val tomorrow: ZonedDateTime = ZonedDateTime.now(UTC).plusDays(1)

    @Nested
    inner class IssueGatewayCertificate {
        @Test
        fun `Subject CommonName should be set to private address of gateway`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(certificate.subjectPrivateAddress, certificate.commonName)
        }

        @Test
        fun `Subject public key should be honored`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(
                identityKeyPair.public.encoded.asList(),
                certificate.certificateHolder.subjectPublicKeyInfo.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be honored`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(identityKeyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Validity end date should be honored`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(
                tomorrow.toEpochSecond(),
                certificate.certificateHolder.notAfter.toInstant().epochSecond
            )
        }

        @Test
        fun `Validity start date should be honored if set`() {
            val startDate = ZonedDateTime.now().minusSeconds(30)
            val certificate = issueGatewayCertificate(
                identityKeyPair.public,
                identityKeyPair.private,
                tomorrow,
                validityStartDate = startDate
            )

            assertEquals(
                startDate.toEpochSecond(),
                certificate.certificateHolder.notBefore.toInstant().epochSecond
            )
        }

        @Test
        fun `Issuer certificate should be honored if set`() {
            val issuerKeyPair = generateRSAKeyPair()
            val issuerCertificate =
                issueGatewayCertificate(issuerKeyPair.public, issuerKeyPair.private, tomorrow)

            val subjectCertificate = issueGatewayCertificate(
                identityKeyPair.public,
                identityKeyPair.private,
                tomorrow,
                issuerCertificate = issuerCertificate
            )

            val issuerCommonNames = subjectCertificate.certificateHolder.issuer.getRDNs(BCStyle.CN)
            assertEquals(
                issuerCertificate.commonName,
                issuerCommonNames.first().first.value.toString()
            )
        }

        @Test
        fun `Subject should be marked as CA`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertTrue(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be 2 if self-issued`() {
            val certificate =
                issueGatewayCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(2, basicConstraints.pathLenConstraint.toInt())
        }

        @Test
        fun `pathLenConstraint should be 1 if issued by another gateway`() {
            val issuerKeyPair = generateRSAKeyPair()
            val issuerCertificate =
                issueGatewayCertificate(issuerKeyPair.public, issuerKeyPair.private, tomorrow)

            val certificate = issueGatewayCertificate(
                identityKeyPair.public,
                identityKeyPair.private,
                tomorrow,
                issuerCertificate = issuerCertificate
            )

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(1, basicConstraints.pathLenConstraint.toInt())
        }
    }

    @Nested
    inner class IssueEndpointCertificate {
        @Test
        fun `CommonName should be set to private address of gateway`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(certificate.subjectPrivateAddress, certificate.commonName)
        }

        @Test
        fun `Subject public key should be honored`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(
                identityKeyPair.public.encoded.asList(),
                certificate.certificateHolder.subjectPublicKeyInfo.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be honored`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(identityKeyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Validity end date should be honored`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertEquals(
                tomorrow.toEpochSecond(),
                certificate.certificateHolder.notAfter.toInstant().epochSecond
            )
        }

        @Test
        fun `Validity start date should be honored if set`() {
            val startDate = ZonedDateTime.now().minusSeconds(30)
            val certificate = issueEndpointCertificate(
                identityKeyPair.public,
                identityKeyPair.private,
                tomorrow,
                validityStartDate = startDate
            )

            assertEquals(
                startDate.toEpochSecond(),
                certificate.certificateHolder.notBefore.toInstant().epochSecond
            )
        }

        @Test
        fun `Issuer certificate should be honored if set`() {
            val issuerKeyPair = generateRSAKeyPair()
            val issuerCertificate =
                issueEndpointCertificate(issuerKeyPair.public, issuerKeyPair.private, tomorrow)

            val subjectCertificate = issueEndpointCertificate(
                identityKeyPair.public,
                identityKeyPair.private,
                tomorrow,
                issuerCertificate = issuerCertificate
            )

            val issuerCommonNames = subjectCertificate.certificateHolder.issuer.getRDNs(BCStyle.CN)
            assertEquals(
                issuerCertificate.commonName,
                issuerCommonNames.first().first.value.toString()
            )
        }

        @Test
        fun `Subject should be marked as CA`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            assertTrue(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be 0`() {
            val certificate =
                issueEndpointCertificate(identityKeyPair.public, identityKeyPair.private, tomorrow)

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(0, basicConstraints.pathLenConstraint.toInt())
        }
    }

    @Nested
    inner class IssueDeliveryAuthorization {
        private val recipientKeyPair = generateRSAKeyPair()
        private val recipientCertificate =
            issueEndpointCertificate(recipientKeyPair.public, recipientKeyPair.private, tomorrow)

        @Test
        fun `Subject CommonName should be set to private address of subject`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            assertEquals(certificate.subjectPrivateAddress, certificate.commonName)
        }

        @Test
        fun `Subject public key should be honored`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            assertEquals(
                identityKeyPair.public.encoded.asList(),
                certificate.certificateHolder.subjectPublicKeyInfo.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be honored`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(recipientKeyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Validity end date should be honored`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            assertEquals(
                tomorrow.toEpochSecond(),
                certificate.certificateHolder.notAfter.toInstant().epochSecond
            )
        }

        @Test
        fun `Validity start date should be honored if set`() {
            val startDate = ZonedDateTime.now().minusSeconds(30)
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate,
                startDate
            )

            assertEquals(
                startDate.toEpochSecond(),
                certificate.certificateHolder.notBefore.toInstant().epochSecond
            )
        }

        @Test
        fun `Subject should not be marked as CA`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            assertFalse(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be 0`() {
            val certificate = issueDeliveryAuthorization(
                identityKeyPair.public,
                recipientKeyPair.private,
                tomorrow,
                recipientCertificate
            )

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(0, basicConstraints.pathLenConstraint.toInt())
        }
    }

    @Nested
    inner class IssueInitialDHKetCertificate {
        private val nodeKeyPair = KeyPairSet.PRIVATE_ENDPOINT
        private val nodeCertificate = PDACertPath.PRIVATE_ENDPOINT

        private val dhKeyPair = generateECDHKeyPair()

        @Test
        fun `Subject CommonName should be that of the node`() {
            val certificate = issueInitialDHKeyCertificate(
                dhKeyPair.public,
                nodeKeyPair.private,
                nodeCertificate,
                tomorrow
            )

            assertEquals(nodeCertificate.commonName, certificate.commonName)
        }

        @Test
        fun `Subject key should be the one specified`() {
            val certificate = issueInitialDHKeyCertificate(
                dhKeyPair.public,
                nodeKeyPair.private,
                nodeCertificate,
                tomorrow
            )

            assertEquals(
                dhKeyPair.public.encoded.asList(),
                certificate.subjectPublicKey.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be that of the node`() {
            val certificate = issueInitialDHKeyCertificate(
                dhKeyPair.public,
                nodeKeyPair.private,
                nodeCertificate,
                tomorrow
            )

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(nodeKeyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Subject should not be marked as CA in Basic Constraints extension`() {
            val certificate = issueInitialDHKeyCertificate(
                dhKeyPair.public,
                nodeKeyPair.private,
                nodeCertificate,
                tomorrow
            )

            assertFalse(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be set to 0`() {
            val certificate = issueInitialDHKeyCertificate(
                dhKeyPair.public,
                nodeKeyPair.private,
                nodeCertificate,
                tomorrow
            )

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(0, basicConstraints.pathLenConstraint.toInt())
        }

        @Nested
        inner class ValidityDates {
            @Test
            fun `Start date should default to current date`() {
                val certificate = issueInitialDHKeyCertificate(
                    dhKeyPair.public,
                    nodeKeyPair.private,
                    nodeCertificate,
                    tomorrow
                )

                assertDateIsAlmostNow(certificate.startDate)
            }

            @Test
            fun `Custom start date should be honored`() {
                val startDate = ZonedDateTime.now().minusMinutes(1).withNano(0)
                val certificate = issueInitialDHKeyCertificate(
                    dhKeyPair.public,
                    nodeKeyPair.private,
                    nodeCertificate,
                    tomorrow,
                    startDate
                )

                assertEquals(startDate, certificate.startDate)
            }

            @Test
            fun `End date should be honored`() {
                val startDate = ZonedDateTime.now()
                val maxEndDate = startDate.plusDays(60).withNano(0)
                val certificate = issueInitialDHKeyCertificate(
                    dhKeyPair.public,
                    nodeKeyPair.private,
                    nodeCertificate,
                    maxEndDate,
                    startDate
                )

                assertEquals(maxEndDate, certificate.expiryDate)
            }

            @Test
            fun `Certificate should not be valid for over 60 days`() {
                val startDate = ZonedDateTime.now().withNano(0)
                val invalidEndDate = startDate.plusDays(60).plusSeconds(1)

                val exception = assertThrows<CertificateException> {
                    issueInitialDHKeyCertificate(
                        dhKeyPair.public,
                        nodeKeyPair.private,
                        nodeCertificate,
                        invalidEndDate,
                        startDate
                    )
                }

                assertEquals("DH key may not be valid for more than 60 days", exception.message)
            }
        }
    }
}
