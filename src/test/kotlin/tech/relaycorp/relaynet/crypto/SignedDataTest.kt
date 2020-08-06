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
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.parseDer
import tech.relaycorp.relaynet.wrappers.cms.HASHING_ALGORITHM_OIDS
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.MessageDigest
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
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
        val anotherStubCertificate = Certificate.issue(
            "Another",
            stubKeyPair.public,
            stubKeyPair.private,
            ZonedDateTime.now().plusDays(1)
        )

        const val cmsDigestAttributeOid = "1.2.840.113549.1.9.4"
    }

    @Nested
    inner class Serialize {
        private val signedData =
            SignedData.sign(stubPlaintext, stubKeyPair.private, stubCertificate)

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
        fun `Empty serialization should be refused`() {
            val invalidCMSSignedData = byteArrayOf()

            val exception = assertThrows<SignedDataException> {
                SignedData.deserialize(invalidCMSSignedData)
            }

            assertEquals("Value cannot be empty", exception.message)
        }

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
                stubCertificate
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
                stubCertificate
            )

            assertEquals(1, signedData.bcSignedData.version)
        }

        @Nested
        inner class Plaintext {
            @Test
            fun `Plaintext should be encapsulated by default when using certificates`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                assertNotNull(signedData.plaintext)
                assertEquals(stubPlaintext.asList(), signedData.plaintext!!.asList())
            }

            @Test
            fun `Plaintext should not be encapsulated if requested when using certificates`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    encapsulatePlaintext = false
                )

                assertNull(signedData.plaintext)
            }

            @Test
            fun `Plaintext should be encapsulated by default when not using certificates`() {
                val signedData = SignedData.sign(stubPlaintext, stubKeyPair.private)

                assertNotNull(signedData.plaintext)
                assertEquals(stubPlaintext.asList(), signedData.plaintext!!.asList())
            }

            @Test
            fun `Plaintext should not be encapsulated if requested when not using certificates`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    encapsulatePlaintext = false
                )

                assertNull(signedData.plaintext)
            }
        }

        @Nested
        inner class SignerInfo {
            @Test
            fun `There should only be one SignerInfo`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                assertEquals(1, signedData.bcSignedData.signerInfos.size())
            }

            @Test
            fun `SignerInfo version should be set to 1 when signed with a certificate`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                assertEquals(1, signerInfo.version)
            }

            @Test
            fun `SignerIdentifier should be IssuerAndSerialNumber when using a certificate`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                assertEquals(stubCertificate.certificateHolder.issuer, signerInfo.sid.issuer)
                assertEquals(
                    stubCertificate.certificateHolder.serialNumber,
                    signerInfo.sid.serialNumber
                )
            }

            @Test
            fun `SignerInfo version should be set to 3 when signed without a certificate`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                assertEquals(1, signerInfo.version)
            }

            @Test
            fun `SignerIdentifier should be SubjectKeyIdentifier when not using a certificate`() {
                val signedData = SignedData.sign(stubPlaintext, stubKeyPair.private)

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                assertNull(signerInfo.sid.issuer)
                assertEquals(byteArrayOf().asList(), signerInfo.sid.subjectKeyIdentifier.asList())
            }

            @Test
            fun `Signature algorithm should be RSA-PSS`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
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
                        stubCertificate
                    )

                    val signerInfo = signedData.bcSignedData.signerInfos.first()

                    assert(0 < signerInfo.signedAttributes.size())
                }

                @Test
                fun `Content type attribute should be set to CMS Data`() {
                    val signedData = SignedData.sign(
                        stubPlaintext,
                        stubKeyPair.private,
                        stubCertificate
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
                        stubCertificate
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
        inner class Certificates {
            @Test
            fun `Signer certificate should not be encapsulated by default`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                assertNull(signedData.signerCertificate)
                assertEquals(0, signedData.certificates.size)
            }

            @Test
            fun `Signer certificate should not be encapsulated when not using certificates`() {
                val signedData = SignedData.sign(stubPlaintext, stubKeyPair.private)

                assertEquals(0, signedData.certificates.size)
            }

            @Test
            fun `CA certificate chain should optionally be encapsulated`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    setOf(stubCertificate, anotherStubCertificate)
                )

                assertEquals(2, signedData.certificates.size)
                assertTrue(signedData.certificates.contains(anotherStubCertificate))
            }
        }

        @Nested
        inner class Hashing {
            @Test
            fun `SHA-256 should be used by default when using certificates`() {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate
                )

                assertHashingAlgoEquals(signedData, HashingAlgorithm.SHA256)
            }

            @ParameterizedTest(name = "{0} should be honored if explicitly set")
            @EnumSource
            fun `Hashing algorithm should be customizable when using certificates`(
                algorithm: HashingAlgorithm
            ) {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    stubCertificate,
                    hashingAlgorithm = algorithm
                )

                assertHashingAlgoEquals(signedData, algorithm)
            }

            @Test
            fun `SHA-256 should be used by default when not using certificates`() {
                val signedData = SignedData.sign(stubPlaintext, stubKeyPair.private)

                assertHashingAlgoEquals(signedData, HashingAlgorithm.SHA256)
            }

            @ParameterizedTest(name = "{0} should be honored if explicitly set")
            @EnumSource
            fun `Hashing algorithm should be customizable when not using certificates`(
                algorithm: HashingAlgorithm
            ) {
                val signedData = SignedData.sign(
                    stubPlaintext,
                    stubKeyPair.private,
                    hashingAlgorithm = algorithm
                )

                assertHashingAlgoEquals(signedData, algorithm)
            }

            private fun assertHashingAlgoEquals(
                signedData: SignedData,
                expectedHashingAlgorithm: HashingAlgorithm
            ) {
                val expectedHashingAlgoOID = HASHING_ALGORITHM_OIDS[expectedHashingAlgorithm]

                assertEquals(1, signedData.bcSignedData.digestAlgorithmIDs.size)
                assertEquals(
                    expectedHashingAlgoOID,
                    signedData.bcSignedData.digestAlgorithmIDs.first().algorithm
                )

                val signerInfo = signedData.bcSignedData.signerInfos.first()
                assertEquals(
                    expectedHashingAlgoOID,
                    signerInfo.digestAlgorithmID.algorithm
                )
            }
        }
    }

    @Nested
    inner class Verify {
        @Test
        fun `Invalid signature with encapsulated plaintext should be refused`() {
            // Swap the SignerInfo collection from two different CMS SignedData values

            val signedData1 = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate)
            )

            val signedData2 = SignedData.sign(
                byteArrayOf(0xde.toByte(), *stubPlaintext),
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate)
            )

            val invalidBCSignedData = CMSSignedData.replaceSigners(
                signedData1.bcSignedData,
                signedData2.bcSignedData.signerInfos
            )
            val invalidSignedData = SignedData.deserialize(invalidBCSignedData.encoded)

            val exception = assertThrows<SignedDataException> { invalidSignedData.verify() }

            assertEquals("Invalid signature", exception.message)
            assertTrue(exception.cause is CMSException)
        }

        @Test
        fun `Invalid signature without encapsulated plaintext should be refused`() {
            // Swap the SignerInfo collection from two different CMS SignedData values

            val signedData1 = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false
            )

            val signedData2 = SignedData.sign(
                byteArrayOf(0xde.toByte(), *stubPlaintext),
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false
            )

            val invalidBCSignedData = CMSSignedData.replaceSigners(
                signedData1.bcSignedData,
                signedData2.bcSignedData.signerInfos
            )
            val invalidSignedData = SignedData.deserialize(invalidBCSignedData.encoded)

            val exception =
                assertThrows<SignedDataException> { invalidSignedData.verify(stubPlaintext) }

            assertEquals("Invalid signature", exception.message)
            assertTrue(exception.cause is CMSException)
        }

        @Test
        fun `Invalid signature with explicit signer key should be refused`() {
            // Do the verification with a different key pair

            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private
            )
            val anotherKeyPair = generateRSAKeyPair()

            val exception = assertThrows<SignedDataException> {
                signedData.verify(signerPublicKey = anotherKeyPair.public)
            }

            assertEquals("Invalid signature", exception.message)
            assertNull(exception.cause)
        }

        @Test
        fun `Signed content should be encapsulated if no specific plaintext is expected`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false
            )

            val exception = assertThrows<SignedDataException> { signedData.verify() }

            assertEquals("Plaintext should be encapsulated or explicitly set", exception.message)
        }

        @Test
        fun `Expected plaintext should be refused if one is already encapsulated`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate)
            )

            val exception = assertThrows<SignedDataException> { signedData.verify(stubPlaintext) }

            assertEquals(
                "No specific plaintext should be expected because one is already encapsulated",
                exception.message
            )
        }

        @Test
        fun `Valid signature with encapsulated plaintext should be accepted`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate)
            )

            cmsSignedData.verify()
        }

        @Test
        fun `Valid signature without encapsulated plaintext should be accepted`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate),
                encapsulatePlaintext = false
            )

            cmsSignedData.verify(stubPlaintext)
        }

        @Test
        fun `Signer certificate should be encapsulated if none is explicitly set`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate
            )

            val exception = assertThrows<SignedDataException> { signedData.verify() }

            assertEquals(
                "Signer certificate should be encapsulated or explicitly set",
                exception.message
            )
        }

        @Test
        fun `Explicit signer key should be refused if a certificate is already encapsulated`() {
            val signedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate)
            )

            val exception = assertThrows<SignedDataException> {
                signedData.verify(signerPublicKey = stubKeyPair.public)
            }

            assertEquals(
                "No specific signer certificate should be expected because one is already " +
                    "encapsulated",
                exception.message
            )
        }

        @Test
        fun `Valid signature with encapsulated signer certificate should succeed`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate)
            )

            cmsSignedData.verify()
        }

        @Test
        fun `Valid signature with explicit signer key should succeed when using certs`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate
            )

            cmsSignedData.verify(signerPublicKey = stubKeyPair.public)
        }

        @Test
        fun `Valid signature with explicit signer key should succeed when not using certs`() {
            val cmsSignedData = SignedData.sign(stubPlaintext, stubKeyPair.private)

            cmsSignedData.verify(signerPublicKey = stubKeyPair.public)
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
                stubCertificate
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
        fun `Certificate of signer may not be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate
            )

            assertNull(cmsSignedData.signerCertificate)
        }

        @Test
        fun `Signer certificate should be output if present`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                setOf(stubCertificate)
            )

            assertEquals(stubCertificate, cmsSignedData.signerCertificate)
        }
    }

    @Nested
    inner class Certificates {
        @Test
        fun `No certificates may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate
            )

            assertEquals(0, cmsSignedData.certificates.size)
        }

        @Test
        fun `One certificate may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate)
            )

            assertEquals(1, cmsSignedData.certificates.size)
            assert(cmsSignedData.certificates.contains(stubCertificate))
        }

        @Test
        fun `Multiple certificates may be encapsulated`() {
            val cmsSignedData = SignedData.sign(
                stubPlaintext,
                stubKeyPair.private,
                stubCertificate,
                encapsulatedCertificates = setOf(stubCertificate, anotherStubCertificate)
            )

            assertEquals(2, cmsSignedData.certificates.size)
            assert(cmsSignedData.certificates.contains(stubCertificate))
            assert(cmsSignedData.certificates.contains(anotherStubCertificate))
        }
    }
}
