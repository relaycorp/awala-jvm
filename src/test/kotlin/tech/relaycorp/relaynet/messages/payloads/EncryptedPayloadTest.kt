package tech.relaycorp.relaynet.messages.payloads

import java.nio.charset.Charset
import kotlin.test.Test
import kotlin.test.assertEquals
import org.bouncycastle.cms.KeyAgreeRecipientInformation
import org.junit.jupiter.api.Nested
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.SymmetricCipher
import tech.relaycorp.relaynet.utils.StubEncryptedPayload
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.PAYLOAD_SYMMETRIC_CIPHER_OIDS
import tech.relaycorp.relaynet.wrappers.cms.SessionEnvelopedData

internal class EncryptedPayloadTest {
    @Nested
    inner class Encrypt {
        private val payloadPlaintext = "plaintext"

        private val recipientSessionKeyPair = SessionKeyPair.generate()
        private val senderSessionKeyPair = SessionKeyPair.generate()

        @Test
        fun `Payload should be encrypted with the specified recipient key`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
                SymmetricCipher.AES_128,
                HashingAlgorithm.SHA256
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized)
            val payloadDecrypted = envelopedData.decrypt(recipientSessionKeyPair.privateKey)
            assertEquals(payloadPlaintext, payloadDecrypted.toString(Charset.defaultCharset()))
        }

        @Test
        fun `Sender's key should have been used in encryption`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
                SymmetricCipher.AES_128,
                HashingAlgorithm.SHA256
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized) as SessionEnvelopedData
            assertEquals(
                senderSessionKeyPair.sessionKey.keyId.asList(),
                envelopedData.getOriginatorKey().keyId.asList()
            )
        }

        @Test
        fun `Cipher AES-128 should be used by default`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[SymmetricCipher.AES_128],
                envelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }

        @ParameterizedTest(name = "Cipher {0} should be used if explicitly requested")
        @EnumSource
        fun symmetricCiphers(algorithm: SymmetricCipher) {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
                algorithm,
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[algorithm],
                envelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }

        @Test
        fun `Hashing algorithm SHA-256 should be used by default`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized)
            val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                KeyAgreeRecipientInformation
            val ecdhAlgorithmOID =
                SessionEnvelopedData.ecdhAlgorithmByHashingAlgorithm[HashingAlgorithm.SHA256]!!
            assertEquals(ecdhAlgorithmOID.id, recipientInfo.keyEncryptionAlgOID)
        }

        @ParameterizedTest(name = "Hashing algorithm {0} should be used if explicitly requested")
        @EnumSource
        fun hashingAlgorithms(algorithm: HashingAlgorithm) {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(
                recipientSessionKeyPair.sessionKey,
                senderSessionKeyPair,
                hashingAlgorithm = algorithm,
            )

            val envelopedData = EnvelopedData.deserialize(payloadSerialized)
            val recipientInfo = envelopedData.bcEnvelopedData.recipientInfos.first() as
                KeyAgreeRecipientInformation
            val ecdhAlgorithmOID =
                SessionEnvelopedData.ecdhAlgorithmByHashingAlgorithm[algorithm]!!
            assertEquals(ecdhAlgorithmOID.id, recipientInfo.keyEncryptionAlgOID)
        }
    }
}
