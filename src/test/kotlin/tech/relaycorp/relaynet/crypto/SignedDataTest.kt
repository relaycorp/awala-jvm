package tech.relaycorp.relaynet.crypto

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
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
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.parseDer
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.cms.SignedDataException
import tech.relaycorp.relaynet.wrappers.cms.verifySignature
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.MessageDigest
import java.time.ZonedDateTime
import kotlin.test.assertEquals

val stubPlaintext = "The plaintext".toByteArray()
val stubKeyPair = generateRSAKeyPair()
val stubCertificate = Certificate.issue(
    "The Common Name",
    stubKeyPair.public,
    stubKeyPair.private,
    ZonedDateTime.now().plusDays(1)
)
val bcCertificate = stubCertificate.certificateHolder
val anotherStubCertificate = Certificate.issue(
    "Another",
    stubKeyPair.public,
    stubKeyPair.private,
    ZonedDateTime.now().plusDays(1)
)
val anotherBCCertificate = anotherStubCertificate.certificateHolder

const val cmsDigestAttributeOid = "1.2.840.113549.1.9.4"

class Serialize {
    private val signedData = SignedData.sign(stubPlaintext, stubKeyPair.private, bcCertificate)

    @Test
    fun `Serialization should be DER-encoded`() {
        parseDer(signedData.serialize())
    }

    @Test
    fun `SignedData value should be wrapped in a ContentInfo value`() {
        ContentInfo.getInstance(parseDer(signedData.serialize()))
    }
}

class Sign {
    @Test
    fun `SignedData version should be set to 1`() {
        val signedData = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate
        )

        assertEquals(1, signedData.bcSignedData.version)
    }

    @Test
    fun `Plaintext should be embedded`() {
        val signedData = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate
        )

        val signedContent = signedData.bcSignedData.signedContent.content
        assert(signedContent is ByteArray)
        assertEquals(stubPlaintext.asList(), (signedContent as ByteArray).asList())
    }

    @Nested
    inner class SignerInfo {
        @Test
        fun `There should only be one SignerInfo`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            assertEquals(1, signedData.bcSignedData.signerInfos.size())
        }

        @Test
        fun `SignerInfo version should be set to 1`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            val signerInfo = signedData.bcSignedData.signerInfos.first()
            assertEquals(1, signerInfo.version)
        }

        @Test
        fun `SignerIdentifier should be IssuerAndSerialNumber`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            val signerInfo = signedData.bcSignedData.signerInfos.first()
            assertEquals(stubCertificate.certificateHolder.issuer, signerInfo.sid.issuer)
            assertEquals(
                stubCertificate.certificateHolder.serialNumber,
                signerInfo.sid.serialNumber
            )
        }

        @Test
        fun `Signature algorithm should be RSA-PSS`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            val signerInfo = signedData.bcSignedData.signerInfos.first()
            assertEquals(PKCSObjectIdentifiers.id_RSASSA_PSS.id, signerInfo.encryptionAlgOID)
        }

        @Nested
        inner class SignedAttributes {
            @Test
            fun `Signed attributes should be present`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    bcCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()

                assert(0 < signerInfo.signedAttributes.size())
            }

            @Test
            fun `Content type attribute should be set to CMS Data`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    bcCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()

                val contentTypeAttrs =
                    signerInfo.signedAttributes.getAll(CMSAttributes.contentType)
                assertEquals(1, contentTypeAttrs.size())
                val contentTypeAttr = contentTypeAttrs.get(0) as Attribute
                assertEquals(1, contentTypeAttr.attributeValues.size)
                assertEquals(CMSObjectIdentifiers.data, contentTypeAttr.attributeValues[0])
            }

            @Test
            fun `Plaintext digest should be present`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    bcCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()

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
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            val attachedCerts =
                (signedData.bcSignedData.certificates as CollectionStore).asSequence().toList()
            assertEquals(1, attachedCerts.size)
            assertEquals(bcCertificate, attachedCerts[0])
        }

        @Test
        fun `CA certificate chain should optionally be attached`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate,
                setOf(anotherBCCertificate)
            )

            val attachedCerts =
                (signedData.bcSignedData.certificates as CollectionStore).asSequence().toSet()
            assertEquals(2, attachedCerts.size)
            assert(attachedCerts.contains(anotherBCCertificate))
        }
    }

    @Nested
    inner class Hashing {
        @Test
        fun `SHA-256 should be used by default`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            assertEquals(1, signedData.bcSignedData.digestAlgorithmIDs.size)
            assertEquals(
                HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA256],
                signedData.bcSignedData.digestAlgorithmIDs.first().algorithm
            )

            val signerInfo = signedData.bcSignedData.signerInfos.first()

            assertEquals(
                HASHING_ALGORITHM_OIDS[HashingAlgorithm.SHA256],
                signerInfo.digestAlgorithmID.algorithm
            )
        }

        @ParameterizedTest(name = "{0} should be honored if explicitly set")
        @EnumSource
        fun `Hashing algorithm should be customizable`(algorithm: HashingAlgorithm) {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate,
                hashingAlgorithm = algorithm
            )

            val hashingAlgorithmOid = HASHING_ALGORITHM_OIDS[algorithm]

            assertEquals(1, signedData.bcSignedData.digestAlgorithmIDs.size)
            assertEquals(
                hashingAlgorithmOid,
                signedData.bcSignedData.digestAlgorithmIDs.first().algorithm
            )

            val signerInfo = signedData.bcSignedData.signerInfos.first()

            assertEquals(hashingAlgorithmOid, signerInfo.digestAlgorithmID.algorithm)
        }
    }
}

class VerifySignatureTest {
    @Test
    fun `Invalid DER values should be refused`() {
        val invalidCMSSignedData = "Not really DER-encoded".toByteArray()

        val exception = assertThrows<SignedDataException> {
            verifySignature(
                invalidCMSSignedData
            )
        }

        assertEquals("Value is not DER-encoded", exception.message)
    }

    @Test
    fun `ContentInfo wrapper should be required`() {
        val invalidCMSSignedData = ASN1Integer(10).encoded

        val exception = assertThrows<SignedDataException> {
            verifySignature(
                invalidCMSSignedData
            )
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
            verifySignature(
                invalidCMSSignedData.encoded
            )
        }

        assertEquals(
            "ContentInfo wraps invalid SignedData value",
            exception.message
        )
    }

    @Test
    fun `Well formed but invalid signatures should be rejected`() {
        // Swap the SignerInfo collection from two different CMS SignedData values

        val signedData1 = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate
        )

        val signedData2 = SignedData.sign(
            byteArrayOf(0xde.toByte(), *stubPlaintext),
            stubKeyPair.private,
            bcCertificate
        )

        val invalidCmsSignedData = CMSSignedData.replaceSigners(
            signedData1.bcSignedData,
            signedData2.bcSignedData.signerInfos
        )
        val invalidCmsSignedDataSerialized = invalidCmsSignedData.toASN1Structure().encoded

        val exception = assertThrows<SignedDataException> {
            verifySignature(
                invalidCmsSignedDataSerialized
            )
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

        val signerBuilder =
            JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").setProvider(BC_PROVIDER)
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

        val signerBuilder =
            JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").setProvider(BC_PROVIDER)
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

        val signerBuilder =
            JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").setProvider(BC_PROVIDER)
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
        val cmsSignedDataSerialized = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate
        ).serialize()

        // No exceptions thrown
        verifySignature(cmsSignedDataSerialized)
    }

    @Test
    fun `Encapsulated content should be output when verification passes`() {
        val cmsSignedDataSerialized = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate
        ).serialize()

        val verificationResult = verifySignature(cmsSignedDataSerialized)

        assertEquals(stubPlaintext.asList(), verificationResult.plaintext.asList())
    }

    @Test
    fun `Signer certificate should be output when verification passes`() {
        val cmsSignedDataSerialized = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate,
            caCertificates = setOf(anotherBCCertificate)
        ).serialize()

        val verificationResult = verifySignature(cmsSignedDataSerialized)

        assertEquals(
            stubCertificate.certificateHolder,
            verificationResult.signerCertificate.certificateHolder
        )
    }

    @Test
    fun `Attached CA certificates should be output when verification passes`() {
        val cmsSignedDataSerialized = SignedData.sign(
            stubPlaintext,
            stubKeyPair.private,
            bcCertificate,
            caCertificates = setOf(anotherBCCertificate)
        ).serialize()

        val verificationResult =
            verifySignature(
                cmsSignedDataSerialized
            )

        assertEquals(2, verificationResult.attachedCertificates.size)
        val attachedCertificateHolders = verificationResult.attachedCertificates.map {
            it.certificateHolder
        }
        assert(attachedCertificateHolders.contains(stubCertificate.certificateHolder))
        assert(attachedCertificateHolders.contains(anotherStubCertificate.certificateHolder))
    }
}
