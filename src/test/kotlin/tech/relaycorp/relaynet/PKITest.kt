package tech.relaycorp.relaynet

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.junit.jupiter.api.Nested
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PKITest {
    val keyPair = generateRSAKeyPair()
    val tomorrow: ZonedDateTime = ZonedDateTime.now(UTC).plusDays(1)

    @Nested
    inner class IssueGatewayCertificate {
        @Test
        fun `CommonName should be set to private address of gateway`() {
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(certificate.subjectPrivateAddress, certificate.commonName)
        }

        @Test
        fun `Subject public key should be honored`() {
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(
                keyPair.public.encoded.asList(),
                certificate.certificateHolder.subjectPublicKeyInfo.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be honored`() {
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(keyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Validity end date should be honored`() {
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(
                tomorrow.toEpochSecond(),
                certificate.certificateHolder.notAfter.toInstant().epochSecond
            )
        }

        @Test
        fun `Validity start date should be honored if set`() {
            val startDate = ZonedDateTime.now().minusSeconds(30)
            val certificate = issueGatewayCertificate(
                keyPair.public,
                keyPair.private,
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
                keyPair.public,
                keyPair.private,
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
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

            assertTrue(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be 2 if self-issued`() {
            val certificate = issueGatewayCertificate(keyPair.public, keyPair.private, tomorrow)

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
                keyPair.public,
                keyPair.private,
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
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(certificate.subjectPrivateAddress, certificate.commonName)
        }

        @Test
        fun `Subject public key should be honored`() {
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(
                keyPair.public.encoded.asList(),
                certificate.certificateHolder.subjectPublicKeyInfo.encoded.asList()
            )
        }

        @Test
        fun `Issuer private key should be honored`() {
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            val verifierProvider = JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(keyPair.public)
            assertTrue(certificate.certificateHolder.isSignatureValid(verifierProvider))
        }

        @Test
        fun `Validity end date should be honored`() {
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            assertEquals(
                tomorrow.toEpochSecond(),
                certificate.certificateHolder.notAfter.toInstant().epochSecond
            )
        }

        @Test
        fun `Validity start date should be honored if set`() {
            val startDate = ZonedDateTime.now().minusSeconds(30)
            val certificate = issueEndpointCertificate(
                keyPair.public,
                keyPair.private,
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
                keyPair.public,
                keyPair.private,
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
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            assertTrue(
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions).isCA
            )
        }

        @Test
        fun `pathLenConstraint should be 0`() {
            val certificate = issueEndpointCertificate(keyPair.public, keyPair.private, tomorrow)

            val basicConstraints =
                BasicConstraints.fromExtensions(certificate.certificateHolder.extensions)
            assertEquals(0, basicConstraints.pathLenConstraint.toInt())
        }
    }
}
