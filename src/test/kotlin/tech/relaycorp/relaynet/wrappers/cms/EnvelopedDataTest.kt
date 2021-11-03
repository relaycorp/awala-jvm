package tech.relaycorp.relaynet.wrappers.cms

import java.util.Hashtable
import javax.crypto.KeyGenerator
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
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
import org.bouncycastle.cms.SimpleAttributeTableGenerator
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.crypto.DataLengthException
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.sha256
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair

private val PLAINTEXT = "hello".toByteArray()

private val ORIGINATOR_KEY_ID_OID = ASN1ObjectIdentifier("0.4.0.127.0.17.0.1.0")

private val SENDER_SESSION_KEY_PAIR = SessionKeyPair.generate()

private val RECIPIENT_SESSION_KEY_PAIR = SessionKeyPair.generate()
private val RECIPIENT_SESSION_KEY = RECIPIENT_SESSION_KEY_PAIR.sessionKey
private val RECIPIENT_SESSION_PRIVATE_KEY = RECIPIENT_SESSION_KEY_PAIR.privateKey

interface RecipientInfoTest {
    fun `There should be exactly one RecipientInfo`()
}

interface EncryptedContentInfoTest {
    fun `Ciphertext corresponding to plaintext should be encapsulated`()
    fun `AES-CBC-128 should be used by default`()
    fun `Symmetric encryption algorithm may be specified explicitly`(
        algorithm: SymmetricCipher
    )
}

interface DecryptTest {
    fun `Decryption with the right key should succeed`()
    fun `Decryption with the wrong key should fail`()
}

typealias AttributeHashtable = Hashtable<ASN1ObjectIdentifier, Attribute>

class EnvelopedDataTest {
    @Nested
    inner class Serialize {
        @Test
        fun `EnvelopedData value should be DER-encoded`() {
            val envelopedData =
                SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
            val envelopedData =
                SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

            val envelopedDataDeserialized = EnvelopedData.deserialize(envelopedData.serialize())
            assertTrue(envelopedDataDeserialized is SessionlessEnvelopedData)
        }

        @Test
        fun `SessionEnvelopedData should be returned if RecipientInfo uses key agreement`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )

            val envelopedDataDeserialized = EnvelopedData.deserialize(envelopedData.serialize())
            assertTrue(envelopedDataDeserialized is SessionEnvelopedData)
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
        inner class RecipientInfo : RecipientInfoTest {
            @Test
            override fun `There should be exactly one RecipientInfo`() {
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                assertEquals(1, envelopedData.bcEnvelopedData.recipientInfos.size())
            }

            @Test
            fun `RecipientInfo should be of type KeyTransRecipientInfo`() {
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first()
                assertTrue(recipientInfo is KeyTransRecipientInformation)
            }

            @Test
            fun `KeyTransRecipientInfo should use issuerAndSerialNumber choice`() {
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

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
        inner class EncryptedContentInfo : EncryptedContentInfoTest {
            @Test
            override fun `Ciphertext corresponding to plaintext should be encapsulated`() {
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                val recipients = envelopedData.bcEnvelopedData.recipientInfos.recipients
                val recipientInfo = recipients.first() as KeyTransRecipientInformation
                val recipient = JceKeyTransEnvelopedRecipient(KeyPairSet.PRIVATE_ENDPOINT.private)
                    .setProvider(BC_PROVIDER)
                val plaintext = recipientInfo.getContent(recipient)
                assertEquals(PLAINTEXT.asList(), plaintext.asList())
            }

            @Test
            override fun `AES-CBC-128 should be used by default`() {
                val envelopedData =
                    SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

                assertEquals(
                    PAYLOAD_SYMMETRIC_CIPHER_OIDS[SymmetricCipher.AES_128],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }

            @ParameterizedTest(name = "{0} should be used if explicitly requested")
            @EnumSource
            override fun `Symmetric encryption algorithm may be specified explicitly`(
                algorithm: SymmetricCipher
            ) {
                val envelopedData = SessionlessEnvelopedData.encrypt(
                    PLAINTEXT,
                    PDACertPath.PRIVATE_ENDPOINT,
                    symmetricCipher = algorithm
                )

                assertEquals(
                    PAYLOAD_SYMMETRIC_CIPHER_OIDS[algorithm],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }
        }

        @Test
        fun `There should be no unprotectedAttrs`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(
                PLAINTEXT,
                PDACertPath.PRIVATE_ENDPOINT,
            )

            assertNull(envelopedData.bcEnvelopedData.unprotectedAttributes)
        }
    }

    @Nested
    inner class Decrypt : DecryptTest {
        @Test
        override fun `Decryption with the right key should succeed`() {
            val envelopedData = SessionlessEnvelopedData.encrypt(
                PLAINTEXT,
                PDACertPath.PRIVATE_ENDPOINT
            )

            val plaintext = envelopedData.decrypt(KeyPairSet.PRIVATE_ENDPOINT.private)

            assertEquals(PLAINTEXT.asList(), plaintext.asList())
        }

        @Test
        override fun `Decryption with the wrong key should fail`() {
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
    inner class Validation {
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
            val envelopedData =
                SessionlessEnvelopedData.encrypt(PLAINTEXT, PDACertPath.PRIVATE_ENDPOINT)

            assertEquals(
                PDACertPath.PRIVATE_ENDPOINT.certificateHolder.serialNumber,
                (envelopedData.getRecipientKeyId() as RecipientSerialNumber).subjectSerialNumber
            )
        }
    }
}

class SessionEnvelopedDataTest {
    @Nested
    inner class Encrypt {
        @Nested
        inner class RecipientInfo : RecipientInfoTest {

            @Test
            override fun `There should be exactly one RecipientInfo`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                assertEquals(1, envelopedData.bcEnvelopedData.recipientInfos.size())
            }

            @Test
            fun `RecipientInfo should be of type KeyAgreeRecipientInfo`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first()
                assertTrue(recipientInfo is KeyAgreeRecipientInformation)
            }

            @Test
            fun `KeyAgreeRecipientInfo should use ECDH with SHA-256 and the X9_63 KDF`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                    KeyAgreeRecipientInformation

                assertEquals(
                    CMSAlgorithm.ECDH_SHA256KDF.id,
                    recipientInfo.keyEncryptionAlgOID
                )
            }

            @ParameterizedTest(name = "{0} should be used if explicitly requested")
            @EnumSource
            fun `Hashing algorithm may be specified explicitly`(
                algorithm: HashingAlgorithm
            ) {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR,
                    hashingAlgorithm = algorithm
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                    KeyAgreeRecipientInformation

                val ecdhAlgorithmOID =
                    SessionEnvelopedData.ecdhAlgorithmByHashingAlgorithm[algorithm]!!
                assertEquals(
                    ecdhAlgorithmOID.id,
                    recipientInfo.keyEncryptionAlgOID
                )
            }

            @Test
            fun `Recipient key should be encrypted with AES-128 by default`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                    KeyAgreeRecipientInformation
                val keyCipher =
                    recipientInfo.keyEncryptionAlgorithm.parameters as AlgorithmIdentifier
                assertEquals(
                    CMSAlgorithm.AES128_WRAP.id,
                    keyCipher.algorithm.id
                )
            }

            @ParameterizedTest(name = "{0}-KW should be used if explicitly requested")
            @EnumSource
            fun `Cipher for recipient key ciphertext may be specified explicitly`(
                algorithm: SymmetricCipher
            ) {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR,
                    symmetricCipher = algorithm
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                    KeyAgreeRecipientInformation
                val keyCipher =
                    recipientInfo.keyEncryptionAlgorithm.parameters as AlgorithmIdentifier
                val expectedKeyCipher = CMS_KW_ALGORITHMS[algorithm]!!
                assertEquals(expectedKeyCipher.id, keyCipher.algorithm.id)
            }

            @Test
            fun `KeyAgreeRecipientIdentifier should use RecipientKeyIdentifier`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                    KeyAgreeRecipientInformation
                assertTrue(recipientInfo.rid is KeyAgreeRecipientId)
                val expectedKeyAgreeRecipientId = KeyAgreeRecipientId(RECIPIENT_SESSION_KEY.keyId)
                assertEquals(expectedKeyAgreeRecipientId, recipientInfo.rid)
            }

            @Test
            fun `Recipient public key should be used`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipients = envelopedData.bcEnvelopedData.recipientInfos.recipients
                val recipientInfo = recipients.first() as KeyAgreeRecipientInformation
                val recipient = JceKeyAgreeEnvelopedRecipient(RECIPIENT_SESSION_PRIVATE_KEY)
                    .setProvider(BC_PROVIDER)
                val plaintext = recipientInfo.getContent(recipient)
                assertEquals(PLAINTEXT.asList(), plaintext.asList())
            }
        }

        @Nested
        inner class EncryptedContentInfo : EncryptedContentInfoTest {
            @Test
            override fun `Ciphertext corresponding to plaintext should be encapsulated`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                val recipients = envelopedData.bcEnvelopedData.recipientInfos.recipients
                val recipientInfo = recipients.first() as KeyAgreeRecipientInformation
                val recipient = JceKeyAgreeEnvelopedRecipient(RECIPIENT_SESSION_PRIVATE_KEY)
                    .setProvider(BC_PROVIDER)
                val plaintext = recipientInfo.getContent(recipient)
                assertEquals(PLAINTEXT.asList(), plaintext.asList())
            }

            @Test
            override fun `AES-CBC-128 should be used by default`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR
                )

                assertEquals(
                    PAYLOAD_SYMMETRIC_CIPHER_OIDS[SymmetricCipher.AES_128],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }

            @ParameterizedTest(name = "{0} should be used if explicitly requested")
            @EnumSource
            override fun `Symmetric encryption algorithm may be specified explicitly`(
                algorithm: SymmetricCipher
            ) {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR,
                    symmetricCipher = algorithm
                )

                assertEquals(
                    PAYLOAD_SYMMETRIC_CIPHER_OIDS[algorithm],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }
        }

        @Nested
        inner class UnprotectedAttrs {
            @Test
            fun `Generated ECDH key id should be included`() {
                val envelopedData = SessionEnvelopedData.encrypt(
                    PLAINTEXT,
                    RECIPIENT_SESSION_KEY,
                    SENDER_SESSION_KEY_PAIR,
                )

                val unprotectedAttrs = envelopedData.bcEnvelopedData.unprotectedAttributes

                val keyIdAttribute = unprotectedAttrs.get(ORIGINATOR_KEY_ID_OID)
                assertEquals(1, keyIdAttribute.attrValues.size())
                val keyIdASN1 = keyIdAttribute.attrValues.getObjectAt(0)
                assertTrue(keyIdASN1 is DEROctetString)
                assertEquals(
                    SENDER_SESSION_KEY_PAIR.sessionKey.keyId.asList(),
                    keyIdASN1.octets.asList()
                )
            }
        }
    }

    @Nested
    inner class Decrypt : DecryptTest {
        @Test
        override fun `Decryption with the right key should succeed`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )

            val plaintext = envelopedData.decrypt(RECIPIENT_SESSION_PRIVATE_KEY)

            assertEquals(PLAINTEXT.asList(), plaintext.asList())
        }

        @Test
        override fun `Decryption with the wrong key should fail`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )
            val anotherKeyPair = generateECDHKeyPair()

            val exception = assertThrows<EnvelopedDataException> {
                envelopedData.decrypt(anotherKeyPair.private)
            }

            assertEquals("Could not decrypt value", exception.message)
            assertTrue(exception.cause is CMSException || exception.cause is DataLengthException)
        }
    }

    @Nested
    inner class GetRecipientKeyId {
        @Test
        fun `Key identifier should be returned`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )

            val actualRecipientKeyId = envelopedData.getRecipientKeyId()
            assertEquals(RECIPIENT_SESSION_KEY.keyId.asList(), actualRecipientKeyId.id.asList())
        }
    }

    @Nested
    inner class GetOriginatorKey {
        @Test
        fun `Key id should be returned`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )

            val originatorKeyId = envelopedData.getOriginatorKey()

            assertEquals(
                SENDER_SESSION_KEY_PAIR.sessionKey.keyId.asList(),
                originatorKeyId.keyId.asList()
            )
        }

        @Test
        fun `Originator DH public key should be returned if it is valid`() {
            val envelopedData = SessionEnvelopedData.encrypt(
                PLAINTEXT,
                RECIPIENT_SESSION_KEY,
                SENDER_SESSION_KEY_PAIR
            )

            val originatorKeyId = envelopedData.getOriginatorKey()

            assertEquals(
                SENDER_SESSION_KEY_PAIR.sessionKey.publicKey,
                originatorKeyId.publicKey
            )
        }
    }

    @Nested
    inner class Validation {
        @Nested
        inner class UnprotectedAttrs {
            @Test
            fun `unprotectedAttrs should be present`() {
                val envelopedDataSerialized = generateEnvelopedData(null)

                val exception = assertThrows<EnvelopedDataException> {
                    EnvelopedData.deserialize(envelopedDataSerialized)
                }

                assertEquals("unprotectedAttrs is missing", exception.message)
            }

            @Test
            fun `unprotectedAttrs should not be empty`() {
                val envelopedDataSerialized = generateEnvelopedData(
                    AttributeHashtable()
                )

                val exception = assertThrows<EnvelopedDataException> {
                    EnvelopedData.deserialize(envelopedDataSerialized)
                }

                assertEquals("unprotectedAttrs is empty", exception.message)
            }

            @Nested
            inner class OriginatorKeyId {
                @Test
                fun `Call should fail if originator key id is missing`() {
                    val unprotectedAttrs = AttributeHashtable()
                    val irrelevantOID = ASN1ObjectIdentifier("1.2.3")
                    unprotectedAttrs[irrelevantOID] = Attribute(
                        irrelevantOID,
                        DERSet()
                    )
                    val envelopedDataSerialized = generateEnvelopedData(unprotectedAttrs)

                    val exception = assertThrows<EnvelopedDataException> {
                        EnvelopedData.deserialize(envelopedDataSerialized)
                    }

                    assertEquals(
                        "Originator key id is missing from unprotectedAttrs",
                        exception.message
                    )
                }

                @Test
                fun `Call should fail if attribute for originator key id is empty`() {
                    val unprotectedAttrs = AttributeHashtable()
                    unprotectedAttrs[OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER] = Attribute(
                        OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
                        DERSet()
                    )
                    val envelopedDataSerialized = generateEnvelopedData(unprotectedAttrs)

                    val exception = assertThrows<EnvelopedDataException> {
                        EnvelopedData.deserialize(envelopedDataSerialized)
                    }

                    assertEquals(
                        "Originator key id is empty",
                        exception.message
                    )
                }

                @Test
                fun `Call should fail if attribute for originator key id is multi-valued`() {
                    val unprotectedAttrs = AttributeHashtable()
                    unprotectedAttrs[OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER] = Attribute(
                        OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
                        DERSet(arrayOf(ASN1Integer(3), ASN1Integer(5)))
                    )
                    val envelopedDataSerialized = generateEnvelopedData(unprotectedAttrs)

                    val exception = assertThrows<EnvelopedDataException> {
                        EnvelopedData.deserialize(envelopedDataSerialized)
                    }

                    assertEquals(
                        "Originator key id has multiple values",
                        exception.message
                    )
                }

                @Test
                fun `Call should fail if attribute for originator key id is not OCTET STRING`() {
                    val unprotectedAttrs = AttributeHashtable()
                    unprotectedAttrs[OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER] = Attribute(
                        OIDs.ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER,
                        DERSet(arrayOf(DERVisibleString("not a number")))
                    )
                    val envelopedDataSerialized = generateEnvelopedData(unprotectedAttrs)

                    val exception = assertThrows<EnvelopedDataException> {
                        EnvelopedData.deserialize(envelopedDataSerialized)
                    }

                    assertEquals(
                        "Originator key id is not an OCTET STRING",
                        exception.message
                    )
                }
            }

            private fun generateEnvelopedData(
                unprotectedAttrs: AttributeHashtable?
            ): ByteArray {
                val cmsEnvelopedDataGenerator = CMSEnvelopedDataGenerator()

                val recipientInfoGenerator =
                    JceKeyAgreeRecipientInfoGenerator(
                        CMSAlgorithm.ECDH_SHA256KDF,
                        SENDER_SESSION_KEY_PAIR.privateKey,
                        SENDER_SESSION_KEY_PAIR.sessionKey.publicKey,
                        CMSAlgorithm.AES128_WRAP
                    ).setProvider(BC_PROVIDER)
                recipientInfoGenerator.addRecipient(
                    RECIPIENT_SESSION_KEY.keyId,
                    RECIPIENT_SESSION_KEY.publicKey
                )
                cmsEnvelopedDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator)

                if (unprotectedAttrs != null) {
                    val unprotectedAttrsGenerator = SimpleAttributeTableGenerator(
                        AttributeTable(unprotectedAttrs)
                    )
                    cmsEnvelopedDataGenerator.setUnprotectedAttributeGenerator(
                        unprotectedAttrsGenerator
                    )
                }

                val bcEnvelopedData = generateBcEnvelopedData(cmsEnvelopedDataGenerator)
                return bcEnvelopedData.encoded
            }
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
