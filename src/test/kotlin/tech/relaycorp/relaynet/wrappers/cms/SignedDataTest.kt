package tech.relaycorp.relaynet.wrappers.cms

import java.security.MessageDigest
import java.time.LocalDateTime
import kotlin.test.assertEquals
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.CollectionStore
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.parseDer
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate

val stubPlaintext = "The plaintext".toByteArray()
val stubKeyPair = generateRSAKeyPair()
val stubCertificate = Certificate.issue(
    "The Common Name",
    stubKeyPair.public,
    stubKeyPair.private,
    LocalDateTime.now().plusDays(1)
)
val anotherStubCertificate = Certificate.issue(
    "Another",
    stubKeyPair.public,
    stubKeyPair.private,
    LocalDateTime.now().plusDays(1)
)

const val cmsDigestAttributeOid = "1.2.840.113549.1.9.4"

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

        @Nested
        inner class SignedAttributes {
            @Test
            fun `Signed attributes should be present`() {
                val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

                val cmsSignedData = parseCmsSignedData(serialization)

                val signerInfo = cmsSignedData.signerInfos.first()

                assert(0 < signerInfo.signedAttributes.size())
            }

            @Test
            fun `Content type attribute should be set to CMS Data`() {
                val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

                val cmsSignedData = parseCmsSignedData(serialization)

                val signerInfo = cmsSignedData.signerInfos.first()

                val cmsContentTypeAttrOid = "1.2.840.113549.1.9.3"
                val contentTypeAttrs =
                    signerInfo.signedAttributes.getAll(ASN1ObjectIdentifier(cmsContentTypeAttrOid))
                assertEquals(1, contentTypeAttrs.size())
                val contentTypeAttr = contentTypeAttrs.get(0) as Attribute
                assertEquals(1, contentTypeAttr.attributeValues.size)
                val cmsDataOid = "1.2.840.113549.1.7.1"
                assertEquals(cmsDataOid, contentTypeAttr.attributeValues[0].toString())
            }

            @Test
            fun `Plaintext digest should be present`() {
                val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

                val cmsSignedData = parseCmsSignedData(serialization)

                val signerInfo = cmsSignedData.signerInfos.first()

                val digestAttrs =
                    signerInfo.signedAttributes.getAll(ASN1ObjectIdentifier(cmsDigestAttributeOid))
                assertEquals(1, digestAttrs.size())
                val digestAttr = digestAttrs.get(0) as Attribute
                assertEquals(1, digestAttr.attributeValues.size)
                val digest = MessageDigest.getInstance("SHA-256").digest(stubPlaintext)
                assertEquals(
                    digest.asList(),
                    (digestAttr.attributeValues[0] as DEROctetString).octets.asList()
                )
            }
        }
    }

    @Nested
    inner class AttachedCertificates {
        @Test
        fun `Signer certificate should be attached`() {
            val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

            val cmsSignedData = parseCmsSignedData(serialization)

            val attachedCerts =
                (cmsSignedData.certificates as CollectionStore).asSequence().toList()
            assertEquals(1, attachedCerts.size)
            assertEquals(stubCertificate.certificateHolder, attachedCerts[0])
        }

        @Test
        fun `CA certificate chain should optionally be attached`() {
            val serialization = sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(anotherStubCertificate)
            )

            val cmsSignedData = parseCmsSignedData(serialization)

            val attachedCerts = (cmsSignedData.certificates as CollectionStore).asSequence().toSet()
            assertEquals(2, attachedCerts.size)
            assert(attachedCerts.contains(anotherStubCertificate.certificateHolder))
        }
    }

    @Nested
    inner class Hashing {
        private val hashingAlgorithmsMap = mapOf(
            HashingAlgorithm.SHA256 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
            HashingAlgorithm.SHA384 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
            HashingAlgorithm.SHA512 to ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3")
        )

        @Test
        fun `SHA-256 should be used by default`() {
            val serialization = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

            val cmsSignedData = parseCmsSignedData(serialization)

            assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
            assertEquals(
                hashingAlgorithmsMap[HashingAlgorithm.SHA256],
                cmsSignedData.digestAlgorithmIDs.first().algorithm
            )

            val signerInfo = cmsSignedData.signerInfos.first()

            assertEquals(
                hashingAlgorithmsMap[HashingAlgorithm.SHA256],
                signerInfo.digestAlgorithmID.algorithm
            )
        }

        @ParameterizedTest(name = "{0} should be honored if explicitly set")
        @EnumSource
        fun `Hashing algorithm should be customizable`(algo: HashingAlgorithm) {
            val serialization =
                sign(stubPlaintext, stubKeyPair.private, stubCertificate, hashingAlgorithm = algo)

            val cmsSignedData = parseCmsSignedData(serialization)

            val hashingAlgorithmOid = hashingAlgorithmsMap[algo]

            assertEquals(1, cmsSignedData.digestAlgorithmIDs.size)
            assertEquals(hashingAlgorithmOid, cmsSignedData.digestAlgorithmIDs.first().algorithm)

            val signerInfo = cmsSignedData.signerInfos.first()

            assertEquals(hashingAlgorithmOid, signerInfo.digestAlgorithmID.algorithm)
        }
    }
}

class VerifySignatureTest {
    @Test
    fun `Invalid DER values should be refused`() {
        val invalidCMSSignedData = "Not really DER-encoded".toByteArray()

        val exception = assertThrows<SignedDataException> {
            verifySignature(invalidCMSSignedData)
        }

        assertEquals("Value is not DER-encoded", exception.message)
    }

    @Test
    fun `ContentInfo wrapper should be required`() {
        val invalidCMSSignedData = ASN1Integer(10).encoded

        val exception = assertThrows<SignedDataException> {
            verifySignature(invalidCMSSignedData)
        }

        assertEquals(
            "SignedData value is not wrapped in ContentInfo",
            exception.message
        )
    }

    @Test
    fun `ContentInfo wrapper should contain a valid SignedData value`() {
        val signedDataOid = ASN1ObjectIdentifier("1.2.840.113549.1.7.2")
        val invalidCMSSignedData = ContentInfo(signedDataOid, ASN1Integer(10))

        val exception = assertThrows<SignedDataException> {
            verifySignature(invalidCMSSignedData.encoded)
        }

        assertEquals(
            "ContentInfo wraps invalid SignedData value",
            exception.message
        )
    }

    @Test
    fun `Well formed but invalid signatures should be rejected`() {
        // Swap the SignerInfo collection from two different CMS SignedData values

        val cmsSignedDataSerialized1 = sign(stubPlaintext, stubKeyPair.private, stubCertificate)
        val cmsSignedData1 = parseCmsSignedData(cmsSignedDataSerialized1)

        val cmsSignedDataSerialized2 = sign(
            byteArrayOf(0xde.toByte(), *stubPlaintext),
            stubKeyPair.private,
            stubCertificate
        )
        val cmsSignedData2 = parseCmsSignedData(cmsSignedDataSerialized2)

        val invalidCmsSignedData = CMSSignedData.replaceSigners(
            cmsSignedData1,
            cmsSignedData2.signerInfos
        )
        val invalidCmsSignedDataSerialized = invalidCmsSignedData.toASN1Structure().encoded

        val exception = assertThrows<SignedDataException> {
            verifySignature(invalidCmsSignedDataSerialized)
        }

        assertEquals("Invalid signature", exception.message)
    }

    @Test
    fun `An empty SignerInfo collection should be refused`() {
        val signedDataGenerator = CMSSignedDataGenerator()
        val plaintextCms: CMSTypedData = CMSProcessableByteArray(stubPlaintext)
        val cmsSignedData = signedDataGenerator.generate(plaintextCms, true)

        val exception = assertThrows<SignedDataException> {
            verifySignature(cmsSignedData.encoded)
        }

        assertEquals("SignedData should contain exactly one SignerInfo (got 0)", exception.message)
    }

    @Test
    fun `A SignerInfo collection with more than one item should be refused`() {
        val signedDataGenerator = CMSSignedDataGenerator()

        val signerBuilder = JcaContentSignerBuilder("SHA256withRSA")
        val contentSigner: ContentSigner = signerBuilder.build(stubKeyPair.private)
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder()
                .build()
        ).build(contentSigner, stubCertificate.certificateHolder)
        // Add the same SignerInfo twice
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator
        )
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator
        )

        val cmsSignedData = signedDataGenerator.generate(
            CMSProcessableByteArray(stubPlaintext),
            true
        )

        val exception = assertThrows<SignedDataException> {
            verifySignature(cmsSignedData.encoded)
        }

        assertEquals("SignedData should contain exactly one SignerInfo (got 2)", exception.message)
    }

    @Test
    fun `Certificate of signer should be required`() {
        val signedDataGenerator = CMSSignedDataGenerator()

        val signerBuilder = JcaContentSignerBuilder("SHA256withRSA")
        val contentSigner: ContentSigner = signerBuilder.build(stubKeyPair.private)
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder()
                .build()
        ).build(contentSigner, stubCertificate.certificateHolder)
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator
        )

        val cmsSignedData = signedDataGenerator.generate(
            CMSProcessableByteArray(stubPlaintext),
            true
        )

        val exception = assertThrows<SignedDataException> {
            verifySignature(cmsSignedData.encoded)
        }

        assertEquals("Certificate of signer should be attached", exception.message)
    }

    @Test
    fun `Signed content should be encapsulated`() {
        val signedDataGenerator = CMSSignedDataGenerator()

        val signerBuilder = JcaContentSignerBuilder("SHA256withRSA")
        val contentSigner: ContentSigner = signerBuilder.build(stubKeyPair.private)
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder()
                .build()
        ).build(contentSigner, stubCertificate.certificateHolder)
        signedDataGenerator.addSignerInfoGenerator(
            signerInfoGenerator
        )

        val certs = JcaCertStore(listOf(stubCertificate.certificateHolder))
        signedDataGenerator.addCertificates(certs)

        val plaintextCms: CMSTypedData = CMSProcessableByteArray(stubPlaintext)
        val cmsSignedData = signedDataGenerator.generate(plaintextCms)

        val exception = assertThrows<SignedDataException> {
            verifySignature(cmsSignedData.encoded)
        }

        assertEquals(
            "Signed plaintext should be encapsulated",
            exception.message
        )
    }

    @Test
    fun `Valid signatures should be accepted`() {
        val cmsSignedDataSerialized = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        // No exceptions thrown
        verifySignature(cmsSignedDataSerialized)
    }

    @Test
    fun `Encapsulated content should be output when verification passes`() {
        val cmsSignedDataSerialized = sign(stubPlaintext, stubKeyPair.private, stubCertificate)

        val verificationResult = verifySignature(cmsSignedDataSerialized)

        assertEquals(stubPlaintext.asList(), verificationResult.plaintext.asList())
    }

    @Test
    fun `Signer certificate should be output when verification passes`() {
        val cmsSignedDataSerialized = sign(
            stubPlaintext,
            stubKeyPair.private,
            stubCertificate,
            caCertificates = setOf(anotherStubCertificate)
        )

        val verificationResult = verifySignature(cmsSignedDataSerialized)

        assertEquals(
            stubCertificate.certificateHolder,
            verificationResult.signerCertificate.certificateHolder
        )
    }

    @Test
    fun `Attached CA certificates should be output when verification passes`() {
        val cmsSignedDataSerialized = sign(
            stubPlaintext,
            stubKeyPair.private,
            stubCertificate,
            caCertificates = setOf(anotherStubCertificate)
        )

        val verificationResult = verifySignature(cmsSignedDataSerialized)

        assertEquals(2, verificationResult.attachedCertificates.size)
        val attachedCertificateHolders = verificationResult.attachedCertificates.map {
            it.certificateHolder
        }
        assert(attachedCertificateHolders.contains(stubCertificate.certificateHolder))
        assert(attachedCertificateHolders.contains(anotherStubCertificate.certificateHolder))
    }
}

private fun parseCmsSignedData(serialization: ByteArray): CMSSignedData {
    val contentInfo = ContentInfo.getInstance(parseDer(serialization))
    return CMSSignedData(contentInfo)
}
