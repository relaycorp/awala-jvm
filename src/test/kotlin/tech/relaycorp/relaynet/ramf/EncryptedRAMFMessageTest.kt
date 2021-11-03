package tech.relaycorp.relaynet.ramf

import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.utils.StubEncryptedPayload
import tech.relaycorp.relaynet.utils.StubEncryptedRAMFMessage
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedDataException
import tech.relaycorp.relaynet.wrappers.cms.SessionlessEnvelopedData

@ExperimentalCoroutinesApi
internal class EncryptedRAMFMessageTest {
    @Nested
    inner class UnwrapPayload {
        private val senderPrivateAddress = PDACertPath.PDA.subjectPrivateAddress
        private val senderSessionKeyPair = SessionKeyPair.generate()

        private val recipientPrivateAddress = PDACertPath.PRIVATE_ENDPOINT.subjectPrivateAddress
        private val recipientSessionKeyPair = SessionKeyPair.generate()

        private val privateKeyStore = MockPrivateKeyStore()

        val payload = StubEncryptedPayload("the payload")

        @BeforeEach
        fun registerSessionKey() = runBlockingTest {
            privateKeyStore.saveSessionKey(
                recipientSessionKeyPair.privateKey,
                recipientSessionKeyPair.sessionKey.keyId,
                senderPrivateAddress,
            )
        }

        @Test
        fun `Exception should be thrown if payload ciphertext is malformed`() = runBlockingTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                "this is not an EnvelopedData value".toByteArray(),
                PDACertPath.PDA,
            )

            assertThrows<EnvelopedDataException> {
                message.unwrapPayload(privateKeyStore)
            }
        }

        @Test
        fun `SessionlessEnvelopedData should not be supported`() = runBlockingTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                SessionlessEnvelopedData.encrypt(
                    payload.serializePlaintext(),
                    PDACertPath.PRIVATE_ENDPOINT
                ).serialize(),
                PDACertPath.PDA
            )

            val exception = assertThrows<InvalidPayloadException> {
                message.unwrapPayload(privateKeyStore)
            }

            assertEquals("SessionlessEnvelopedData is no longer supported", exception.message)
        }

        @Test
        fun `Exception should be thrown if session key does not exist`() = runBlockingTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )
            privateKeyStore.clear()

            assertThrows<MissingKeyException> {
                message.unwrapPayload(privateKeyStore)
            }
        }

        @Test
        fun `SessionEnvelopedData payload should be decrypted`() = runBlockingTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (plaintextDeserialized) = message.unwrapPayload(privateKeyStore)

            assertEquals(payload.payload, plaintextDeserialized.payload)
        }

        @Test
        fun `Peer's session key should be output`() = runBlockingTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (_, senderSessionKey) = message.unwrapPayload(privateKeyStore)

            assertEquals(senderSessionKeyPair.sessionKey, senderSessionKey)
        }
    }
}
