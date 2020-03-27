package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.KeyTransRecipientId
import org.bouncycastle.cms.KeyTransRecipientInformation
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private val PLAINTEXT = "hello".toByteArray()
private val KEYPAIR = generateRSAKeyPair()
private val CERTIFICATE = issueStubCertificate(KEYPAIR.public, KEYPAIR.private)

class SessionlessEnvelopedDataTest {
    @Nested
    inner class Encrypt {
        @Nested
        inner class RecipientInfo {
            @Test
            fun `There should be exactly one RecipientInfo`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

                assertEquals(1, envelopedData.bcEnvelopedData.recipientInfos.size())
            }

            @Test
            fun `RecipientInfo should be of type KeyTransRecipientInfo`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

                val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first()
                assertTrue(recipientInfo is KeyTransRecipientInformation)
            }

            @Test
            fun `KeyTransRecipientInfo should use issuerAndSerialNumber choice`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

                val recipientInfo =
                    envelopedData.bcEnvelopedData.recipientInfos.first() as
                        KeyTransRecipientInformation
                assertTrue(recipientInfo.rid is KeyTransRecipientId)
                assertEquals(
                    CERTIFICATE.certificateHolder.issuer,
                    (recipientInfo.rid as KeyTransRecipientId).issuer
                )
                assertEquals(
                    CERTIFICATE.certificateHolder.serialNumber,
                    (recipientInfo.rid as KeyTransRecipientId).serialNumber
                )
            }

            @Test
            fun `KeyTransRecipientInfo should use RSA-OAEP`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

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
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

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
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

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
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

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
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

                val recipients = envelopedData.bcEnvelopedData.recipientInfos.recipients
                val recipientInfo = recipients.iterator().next() as KeyTransRecipientInformation
                val recipient = JceKeyTransEnvelopedRecipient(KEYPAIR.private).setProvider(
                    BouncyCastleProvider()
                )

                assertEquals(PLAINTEXT.asList(), recipientInfo.getContent(recipient).asList())
            }

            @Test
            fun `AES-GCM-128 should be used by default`() {
                val envelopedData = SessionlessEnvelopedData.encrypt(PLAINTEXT, CERTIFICATE)

                assertEquals(
                    SYMMETRIC_ENC_ALGORITHM_OIDS[SymmetricEncryption.AES_GCM_128],
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
                    CERTIFICATE,
                    symmetricEncryptionAlgorithm = algorithm
                )

                assertEquals(
                    SYMMETRIC_ENC_ALGORITHM_OIDS[algorithm],
                    envelopedData.bcEnvelopedData.encryptionAlgOID
                )
            }
        }
    }
}
