package tech.relaycorp.relaynet.ramf

import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
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
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair

@ExperimentalCoroutinesApi
internal class EncryptedRAMFMessageTest {
    private val senderPrivateAddress = PDACertPath.PDA.subjectPrivateAddress
    private val senderSessionKeyPair = SessionKeyPair.generate()

    private val recipientPrivateAddress = PDACertPath.PRIVATE_ENDPOINT.subjectPrivateAddress
    private val recipientSessionKeyPair = SessionKeyPair.generate()

    private val payload = StubEncryptedPayload("the payload")

    @Nested
    inner class UnwrapPayload {
        private val privateKeyStore = MockPrivateKeyStore()

        @BeforeEach
        fun registerSessionKey() = runTest {
            privateKeyStore.saveSessionKey(
                recipientSessionKeyPair.privateKey,
                recipientSessionKeyPair.sessionKey.keyId,
                recipientPrivateAddress,
                senderPrivateAddress,
            )
        }

        @Test
        fun `Exception should be thrown if payload ciphertext is malformed`() = runTest {
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
        fun `SessionlessEnvelopedData should not be supported`() = runTest {
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
        fun `Exception should be thrown if session key does not exist`() = runTest {
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
        fun `SessionEnvelopedData payload should be decrypted`() = runTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (plaintextDeserialized) = message.unwrapPayload(privateKeyStore)

            assertEquals(payload.payload, plaintextDeserialized.payload)
        }

        @Test
        fun `Peer's session key should be output`() = runTest {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (_, senderSessionKey) = message.unwrapPayload(privateKeyStore)

            assertEquals(senderSessionKeyPair.sessionKey, senderSessionKey)
        }

        @Test
        fun `Messages bound for a public node shouldn't be supported`() = runTest {
            val message = StubEncryptedRAMFMessage(
                "https://example.com",
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val exception = assertThrows<NotImplementedError> {
                message.unwrapPayload(privateKeyStore)
            }

            assertContains(exception.message!!, "Public recipients are not currently supported")
        }
    }

    @Nested
    inner class UnwrapPayloadWithPrivateKey {
        @Test
        fun `Exception should be thrown if payload ciphertext is malformed`() {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                "this is not an EnvelopedData value".toByteArray(),
                PDACertPath.PDA,
            )

            assertThrows<EnvelopedDataException> {
                message.unwrapPayload(recipientSessionKeyPair.privateKey)
            }
        }

        @Test
        fun `SessionlessEnvelopedData should not be supported`() {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                SessionlessEnvelopedData.encrypt(
                    payload.serializePlaintext(),
                    PDACertPath.PRIVATE_ENDPOINT
                ).serialize(),
                PDACertPath.PDA
            )

            val exception = assertThrows<InvalidPayloadException> {
                message.unwrapPayload(recipientSessionKeyPair.privateKey)
            }

            assertEquals("SessionlessEnvelopedData is no longer supported", exception.message)
        }

        @Test
        fun `Exception should be thrown if wrong private key is passed`() {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )
            val wrongPrivateKey = generateECDHKeyPair().private

            assertThrows<EnvelopedDataException> {
                message.unwrapPayload(wrongPrivateKey)
            }
        }

        @Test
        fun `SessionEnvelopedData payload should be decrypted`() {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (plaintextDeserialized) = message.unwrapPayload(recipientSessionKeyPair.privateKey)

            assertEquals(payload.payload, plaintextDeserialized.payload)
        }

        @Test
        fun `Peer's session key should be output`() {
            val message = StubEncryptedRAMFMessage(
                recipientPrivateAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                PDACertPath.PDA,
            )

            val (_, senderSessionKey) = message.unwrapPayload(recipientSessionKeyPair.privateKey)

            assertEquals(senderSessionKeyPair.sessionKey, senderSessionKey)
        }
    }
}
