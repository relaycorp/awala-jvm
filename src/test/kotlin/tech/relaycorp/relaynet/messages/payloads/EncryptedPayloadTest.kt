package tech.relaycorp.relaynet.messages.payloads

import java.nio.charset.Charset
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.SymmetricEncryption
import tech.relaycorp.relaynet.utils.CERTIFICATE
import tech.relaycorp.relaynet.utils.KEY_PAIR
import tech.relaycorp.relaynet.utils.StubEncryptedPayload
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.PAYLOAD_SYMMETRIC_CIPHER_OIDS

internal class EncryptedPayloadTest {
    @Nested
    inner class Encrypt {
        private val payloadPlaintext = "plaintext"

        @Test
        fun `Payload should be encrypted with the specified certificate`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(CERTIFICATE)

            val payloadCmsEnvelopedData = EnvelopedData.deserialize(payloadSerialized)
            val payloadDecrypted = payloadCmsEnvelopedData.decrypt(KEY_PAIR.private)
            assertEquals(payloadPlaintext, payloadDecrypted.toString(Charset.defaultCharset()))
        }

        @Test
        fun `Payload should be encrypted with AES-128 by default`() {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(CERTIFICATE)

            val payloadCmsEnvelopedData = EnvelopedData.deserialize(payloadSerialized)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[SymmetricEncryption.AES_128],
                payloadCmsEnvelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }

        @ParameterizedTest(name = "{0} should be used if explicitly requested")
        @EnumSource
        fun `Encryption algorithm can be customized`(algorithm: SymmetricEncryption) {
            val payload = StubEncryptedPayload(payloadPlaintext)

            val payloadSerialized = payload.encrypt(CERTIFICATE, algorithm)

            val payloadCmsEnvelopedData = EnvelopedData.deserialize(payloadSerialized)
            assertEquals(
                PAYLOAD_SYMMETRIC_CIPHER_OIDS[algorithm],
                payloadCmsEnvelopedData.bcEnvelopedData.encryptionAlgOID
            )
        }
    }
}
