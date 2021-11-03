package tech.relaycorp.relaynet.ramf

import kotlin.test.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.SessionKey
import tech.relaycorp.relaynet.utils.ID_CERTIFICATE
import tech.relaycorp.relaynet.utils.StubEncryptedPayload
import tech.relaycorp.relaynet.utils.StubEncryptedRAMFMessage

internal class EncryptedRAMFMessageTest {
    private val recipientAddress = "04334"

    private val recipientSessionKeyPair = SessionKey.generate()
    private val senderSessionKeyPair = SessionKey.generate()

    @Nested
    inner class UnwrapPayload {
        @Test
        fun `SessionEnvelopedData payload should be decrypted`() {
            val payload = StubEncryptedPayload("the payload")
            val message = StubEncryptedRAMFMessage(
                recipientAddress,
                payload.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                ID_CERTIFICATE
            )

            val plaintextDeserialized = message.unwrapPayload(recipientSessionKeyPair.privateKey)

            assertEquals(payload.payload, plaintextDeserialized.payload)
        }
    }
}
