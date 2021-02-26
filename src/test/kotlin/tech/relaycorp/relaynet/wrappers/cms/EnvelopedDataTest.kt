package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.KeyAgreeRecipientId
import org.bouncycastle.cms.KeyAgreeRecipientInformation
import org.bouncycastle.cms.KeyTransRecipientId
import org.bouncycastle.cms.KeyTransRecipientInformation
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.crypto.DataLengthException
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.PDACertPath
import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.sha256
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import javax.crypto.KeyGenerator
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private val PLAINTEXT = "hello".toByteArray()

class EnvelopedDataTest {
    @Nested
    inner class Serialize {
        @Test
        fun `EnvelopedData value should be DER-encoded`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

            val serialization = envelopedData.serialize()

            CMSEnvelopedData(serialization)
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Invalid CMS EnvelopedData serializations should be refused`() {
            val exception = assertThrows<EnvelopedDataException> {
                EnvelopedData.deserialize("Not really EnvelopedData".toByteArray())
            }

            assertEquals("Value should be a DER-encoded CMS EnvelopedData", exception.message)
            assertTrue(exception.cause is CMSException)
        }

        @Test
        fun `EnvelopedData should not have zero recipients`() {
            val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()
            val bcEnvelopedData = generateBcEnvelopedData(cmsEnvelopedDataGenerator)

            val exception = assertThrows<EnvelopedDataException> {
                EnvelopedData.deserialize(bcEnvelopedData.encoded)
            }

            assertEquals("Exactly one RecipientInfo is required (got 0)", exception.message)
        }

        @Test
        fun `EnvelopedData value should not have two or more recipients`() {
            val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

            val x509Certificate = JcaX509CertificateConverter()
                .getCertificate(PDACertPath.PRIVATE_ENDPOINT.certificateHolder)
            val transKeyGen =
                JceKeyTransRecipientInfoGenerator(x509Certificate).setProvider(BC_PROVIDER)
            // Add the same recipient twice
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen)
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen)

            val bcEnvelopedData = generateBcEnvelopedData(cmsEnvelopedDataGenerator)

            val exception = assertThrows<EnvelopedDataException> {
                EnvelopedData.deserialize(bcEnvelopedData.encoded)
            }

            assertEquals(
                "Exactly one RecipientInfo is required (got 2)",
                exception.message
            )
        }

        @Test
        fun `SessionlessEnvelopedData should be returned if RecipientInfo uses key transport`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

            val envelopedDataDeserialized = EnvelopedData.deserialize(envelopedData.serialize())
            assertTrue(envelopedDataDeserialized is SessionlessEnvelopedData)
        }

        @Test
        fun `Unsupported RecipientInfo types should result in an error`() {
            // Use a KEKRecipientInfo

            val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

            val kekId = byteArrayOf(1, 2, 3, 4, 5)
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(128)
            val recipientInfoGenerator = JceKEKRecipientInfoGenerator(kekId, keyGen.generateKey())
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator)

            val bcEnvelopedData = generateBcEnvelopedData(cmsEnvelopedDataGenerator)

            val exception = assertThrows<EnvelopedDataException> {
                EnvelopedData.deserialize(bcEnvelopedData.encoded)
            }

            assertEquals(
                "Unsupported RecipientInfo (got KEKRecipientInformation)",
                exception.message
            )
        }
    }
}

class SessionlessEnvelopedDataTest {
    @Nested
    inner class Encrypt {
        @Nested
        inner class RecipientInfo {
            @Test
            fun `There should be exactly one RecipientInfo`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                assertEquals(1, envelopedData.bcEnvelopedData.recipientInfos.size())
            }

            @Test
            fun `RecipientInfo should be of type KeyTransRecipientInfo`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first()
                assertTrue(recipientInfo is KeyTransRecipientInformation)
            }

            @Test
            fun `KeyTransRecipientInfo should use issuerAndSerialNumber choice`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation
                assertTrue(recipientInfo.rid is KeyTransRecipientId)
                assertEquals(
                    PDACertPath.PRIVATE_ENDPOINT.certificateHolder.issuer,
                    (recipientInfo.rid as KeyTransRecipientId).issuer
                )
                assertEquals(
                    PDACertPath.PRIVATE_ENDPOINT.certificateHolder.serialNumber,
                    (recipientInfo.rid as KeyTransRecipientId).serialNumber
                )
            }

            @Test
            fun `KeyTransRecipientInfo should use RSA-OAEP`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation

                assertEquals(
                    PKCSObjectIdentifiers.id_RSAES_OAEP.id,
                    recipientInfo.keyEncryptionAlgOID
                )
            }

            @Test
            fun `RSA-OAEP should be used with SHA-256`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation

                val oaepParams = recipientInfo.keyEncryptionAlgorithm.parameters
                assertTrue(oaepParams is RSAESOAEPparams)
                assertEquals(
                    NISTObjectIdentifiers.id_sha256,
                    oaepParams.hashAlgorithm.algorithm
                )
            }

            @Test
            fun `MGF should be MGF1 with SHA-256`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation

                val oaepParams = recipientInfo.keyEncryptionAlgorithm.parameters
                assertTrue(oaepParams is RSAESOAEPparams)
                assertEquals(
                    PKCSObjectIdentifiers.id_mgf1,
                    oaepParams.maskGenAlgorithm.algorithm
                )
                assertEquals(
                    NISTObjectIdentifiers.id_sha256,
                    (oaepParams.maskGenAlgorithm.parameters as AlgorithmIdentifier).algorithm
                )
            }

            @Test
            fun `RSA-OAEP should be used with default P source algorithm`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation

                val oaepParams = recipientInfo.keyEncryptionAlgorithm.parameters
                assertTrue(oaepParams is RSAESOAEPparams)
                assertEquals(
                    RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM,
                    oaepParams.pSourceAlgorithm
                )
            }
        }

        @Nested
        inner class EncryptedContentInfo {
            @Test
            fun `Ciphertext corresponding to plaintext should be encapsulated`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipients = envelopedData.bcEnvelopedData.recipientInfos.recipients
                val recipientInfo = recipients.first() as KeyTransRecipientInformation
                val recipient =
                    JceKeyTransEnvelopedRecipient(KeyPairSet.PRIVATE_ENDPOINT.private).setProvider(BC_PROVIDER)
                val plaintext = recipientInfo.getContent(recipient)
                assertEquals(PLAINTEXT.asList(), plaintext.asList())
            }

            @Test
            fun `AES-CBC-128 should be used by default`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                assertEquals(
                    PAYLOAD_SYMMETRIC_ENC_ALGO_OIDS[SymmetricEncryption.AES_128],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }

            @ParameterizedTest(name = "{0} should be used if explicitly requested")
            @EnumSource
            fun `Symmetric encryption algorithm may be specified explicitly`(
                algorithm: SymmetricEncryption
            ) {
                val envelopedData = SessionlessEnvelopedData.encrypt(
                    PLAINTEXT,
                    PDACertPath.PRIVATE_ENDPOINT,
                    symmetricEncryptionAlgorithm = algorithm
                )

                assertEquals(
                    PAYLOAD_SYMMETRIC_ENC_ALGO_OIDS[algorithm],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }
        }
    }

    @Nested
    inner class Decrypt {
        @Test
        fun `Decryption with the right key should succeed`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(
                PLAINTEXT,
                PDACertPath.PRIVATE_ENDPOINT
            )

            val plaintext = envelopedData.decrypt(KeyPairSet.PRIVATE_ENDPOINT.private)

            assertEquals(PLAINTEXT.asList(), plaintext.asList())
        }

        @Test
        fun `Decryption with the wrong key should fail`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(
                PLAINTEXT,
                PDACertPath.PRIVATE_ENDPOINT
            )
            val anotherKeyPair = generateRSAKeyPair()

            val exception = assertThrows<EnvelopedDataException> {
                envelopedData.decrypt(anotherKeyPair.private)
            }

            assertEquals("Could not decrypt value", exception.message)
            assertTrue(exception.cause is CMSException || exception.cause is DataLengthException)
        }
    }

    @Nested
    inner class PostDeserializationValidation {
        @Nested
        inner class RecipientKeyId {
            @Test
            fun `Recipient key id should not be a SubjectKeyIdentifier`() {
                val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

                val transKeyGen = JceKeyTransRecipientInfoGenerator(
                    sha256(KeyPairSet.PRIVATE_ENDPOINT.public.encoded),
                    KeyPairSet.PRIVATE_ENDPOINT.public
                ).setProvider(BC_PROVIDER)
                cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen)

                val bcEnvelopedData = generateBcEnvelopedData(cmsEnvelopedDataGenerator)

                // Make sure we're actually using SubjectKeyIdentifier before the actual test
                val rid = bcEnvelopedData.recipientInfos.first().rid as KeyTransRecipientId
                assertEquals(null, rid.issuer)
                assertEquals(null, rid.serialNumber)
                assertNotEquals(null, rid.subjectKeyIdentifier)
                val exception = assertThrows<EnvelopedDataException> {
                    EnvelopedData.deserialize(bcEnvelopedData.encoded)
                }

                assertEquals(
                    "Required recipient key id to be IssuerAndSerialNumber " +
                        "(got SubjectKeyIdentifier)",
                    exception.message
                )
            }
        }
    }

    @Nested
    inner class GetRecipientKeyId {
        @Test
        fun `Key id should be returned`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

            val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first()
            assertEquals(
                (recipientInfo.rid as KeyTransRecipientId).serialNumber,
                envelopedData.getRecipientKeyId()
            )
        }
    }
}

private fun generateBcEnvelopedData(
    cmsEnvelopedDataGenerator: CMSEnvelopedDataGenerator
): CMSEnvelopedData {
    val msg = CMSProcessableByteArray(PLAINTEXT)
    val encryptorBuilder =
        JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC_PROVIDER)
    return cmsEnvelopedDataGenerator.generate(msg, encryptorBuilder.build())
}
