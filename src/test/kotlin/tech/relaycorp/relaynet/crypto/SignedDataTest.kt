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
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.MessageDigest
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SignedDataTest {
    companion object {
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
    }

    @Nested
    inner class Serialize {
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

    @Nested
    inner class Deserialize {
        @Test
        fun `Invalid DER values should be refused`() {
            val invalidCMSSignedData = "Not really DER-encoded".toByteArray()

            val exception = assertThrows<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
            }

            assertEquals("Value is not DER-encoded", exception.message)
        }

        @Test
        fun `ContentInfo wrapper should be required`() {
            val invalidCMSSignedData = ASN1Integer(10).encoded

            val exception = assertThrows<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
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
                SignedData.deserialize(invalidCMSSignedData.encoded)
            }

            assertEquals(
                "ContentInfo wraps invalid SignedData value",
                exception.message
            )
        }

        @Test
        fun `Valid SignedData values should be deserialized`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )
            val signedDataSerialized = signedData.serialize()

            val signedDataDeserialized = SignedData.deserialize(signedDataSerialized)

            assertEquals(
                signedData.bcSignedData.encoded.asList(),
                signedDataDeserialized.bcSignedData.encoded.asList()
            )
        }
    }

    @Nested
    inner class Sign {
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
                        signerInfo.signedAttributes.getAll(
                            ASN1ObjectIdentifier(
                                cmsDigestAttributeOid
                            )
                        )
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

    @Nested
    inner class Verify {
        @Test
        fun `Well formed but invalid signatures should be refused`() {
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

            val invalidBCSignedData = CMSSignedData.replaceSigners(
                signedData1.bcSignedData,
                signedData2.bcSignedData.signerInfos
            )
            val invalidSignedData = SignedData.deserialize(invalidBCSignedData.encoded)

            val exception = assertThrows<SignedDataException> { invalidSignedData.verify() }

            assertEquals("Invalid signature", exception.message)
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
            val bcSignedData = signedDataGenerator.generate(plaintextCms)
            val signedData = SignedData.deserialize(bcSignedData.encoded)

            val exception = assertThrows<SignedDataException> { signedData.verify() }

            assertEquals(
                "Signed plaintext should be encapsulated",
                exception.message
            )
        }

        @Test
        fun `Valid signatures should be accepted`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            // No exceptions thrown
            cmsSignedData.verify()
        }
    }

    @Nested
    inner class Plaintext {
        @Test
        fun `Plaintext should be null if not encapsulated`() {
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
            val bcSignedData = signedDataGenerator.generate(plaintextCms, false)
            val signedData = SignedData.deserialize(bcSignedData.encoded)

            assertNull(signedData.plaintext)
        }

        @Test
        fun `Plaintext should be output if encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            assertTrue(cmsSignedData.plaintext is ByteArray)
            assertEquals(stubPlaintext.asList(), cmsSignedData.plaintext!!.asList())
        }
    }

    @Nested
    inner class SignerCertificate {
        @Test
        fun `An empty SignerInfo collection should be refused`() {
            val signedDataGenerator = CMSSignedDataGenerator()
            val plaintextCms: CMSTypedData = CMSProcessableByteArray(stubPlaintext)
            val bcSignedData = signedDataGenerator.generate(plaintextCms, true)
            val signedData = SignedData(bcSignedData)

            val exception = assertThrows<SignedDataException> { signedData.signerCertificate }

            assertEquals(
                "SignedData should contain exactly one SignerInfo (got 0)",
                exception.message
            )
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

            val bcSignedData = signedDataGenerator.generate(
                CMSProcessableByteArray(stubPlaintext),
                true
            )
            val signedData = SignedData(bcSignedData)

            val exception = assertThrows<SignedDataException> { signedData.signerCertificate }

            assertEquals(
                "SignedData should contain exactly one SignerInfo (got 2)",
                exception.message
            )
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

            val bcSignedData = signedDataGenerator.generate(
                CMSProcessableByteArray(stubPlaintext),
                true
            )
            val signedData = SignedData(bcSignedData)

            val exception = assertThrows<SignedDataException> { signedData.signerCertificate }

            assertEquals("Certificate of signer should be attached", exception.message)
        }

        @Test
        fun `Signer certificate should be output if present`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate
            )

            assertEquals(bcCertificate, cmsSignedData.signerCertificate)
        }
    }

    @Nested
    inner class AttachedCertificates {
        @Test
        fun `Attached CA certificates should be output`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                bcCertificate,
                caCertificates = setOf(anotherBCCertificate)
            )

            assertEquals(2, cmsSignedData.attachedCertificates.size)
            assert(cmsSignedData.attachedCertificates.contains(bcCertificate))
            assert(cmsSignedData.attachedCertificates.contains(anotherBCCertificate))
        }
    }
}
