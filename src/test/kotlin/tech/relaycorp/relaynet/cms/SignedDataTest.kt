package tech.relaycorp.relaynet.cms

import kotlin.test.assertEquals
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSSignedData
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.parseDer
import tech.relaycorp.relaynet.x509.Certificate
import tech.relaycorp.relaynet.x509.FullCertificateIssuanceOptions
import tech.relaycorp.relaynet.x509.Keys

val stubPlaintext = "The plaintext".toByteArray()
val stubKeyPair = Keys.generateRSAKeyPair(2048)
val stubCertificate = Certificate.issue(
    FullCertificateIssuanceOptions(
        Certificate.buildX500Name("The C Name"),
        stubKeyPair.private,
        stubKeyPair.public,
        issuerCertificate = null
    )
)

class Sign {
    @Test
    fun `Serialization should be DER-encoded`() {
        val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        parseDer(serialization)
    }

    @Test
    fun `SignedData value should be wrapped in a ContentInfo value`() {
        val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        ContentInfo.getInstance(parseDer(serialization))
    }

    @Test
    fun `SignedData version should be set to 1`() {
        val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        val cmsSignedData = parseCmsSignedData(serialization)

        assertEquals(1, cmsSignedData.version)
    }

    @Test
    fun `Plaintext should be embedded`() {
        val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        val cmsSignedData = parseCmsSignedData(serialization)

        val signedContent = cmsSignedData.signedContent.content
        assert(signedContent is ByteArray)
        assertEquals(stubPlaintext.asList(), (signedContent as ByteArray).asList())
    }

    @Nested
    inner class SignerInfo {
        @Test
        fun `There should only be one SignerInfo`() {
            val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

            val cmsSignedData = parseCmsSignedData(serialization)

            assertEquals(1, cmsSignedData.signerInfos.size())
        }

        @Test
        fun `SignerInfo version should be set to 1`() {
            val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

            val cmsSignedData = parseCmsSignedData(serialization)

            val signerInfo = cmsSignedData.signerInfos.first()
            assertEquals(1, signerInfo.version)
        }

        @Test
        fun `SignerIdentifier should be IssuerAndSerialNumber`() {
            val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

            val cmsSignedData = parseCmsSignedData(serialization)

            val signerInfo = cmsSignedData.signerInfos.first()
            assertEquals(stubCertificate.certificateHolder.issuer, signerInfo.sid.issuer)
            assertEquals(
                stubCertificate.certificateHolder.serialNumber,
                signerInfo.sid.serialNumber
            )
        }
    }

    @Nested
    inner class SignedAttributes {
        @Test
        @Disabled
        fun `Signed attributes should be present`() {
        }

        @Test
        @Disabled
        fun `Content type attribute should be set to CMS Data`() {
        }

        @Test
        @Disabled
        fun `Plaintext digest should be present`() {
        }
    }

    @Nested
    inner class AttachedCertificates {
        @Test
        @Disabled
        fun `Signer certificate should be attached`() {
        }

        @Test
        @Disabled
        fun `CA certificate chain should optionally be attached`() {
        }
    }

    @Nested
    inner class HashingAlgorithms {
        @Test
        @Disabled
        fun `SHA-256 should be used by default`() {
        }

        @Test
        @Disabled
        fun `SHA-384 should be supported`() {
        }

        @Test
        @Disabled
        fun `SHA-512 should be supported`() {
        }

        @Test
        @Disabled
        fun `SHA-1 should not be supported`() {
        }

        @Test
        @Disabled
        fun `MD5 should not be supported`() {
        }
    }

    private fun parseCmsSignedData(serialization: ByteArray): CMSSignedData {
        val contentInfo = ContentInfo.getInstance(parseDer(serialization))
        return CMSSignedData(contentInfo)
    }
}

class VerifySignatureTest {
    @Test
    @Disabled
    fun `Invalid DER values should be refused`() {
    }

    @Test
    @Disabled
    fun `Well formed but invalid signatures should be rejected`() {
    }

    @Test
    @Disabled
    fun `Valid signatures should be accepted`() {
    }

    @Test
    @Disabled
    fun `Signer certificate should be output when verification passes`() {
    }

    @Test
    @Disabled
    fun `Attached CA certificates should be output when verification passes`() {
    }
}
