package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedDataException
import tech.relaycorp.relaynet.wrappers.cms.SessionlessEnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey
import java.time.ZonedDateTime

public abstract class EncryptedRAMFMessage<P : EncryptedPayload> internal constructor(
    serializer: RAMFSerializer,
    recipientAddress: String,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String?,
    creationDate: ZonedDateTime?,
    ttl: Int?,
    senderCertificateChain: Set<Certificate>?
) : RAMFMessage<P>(
    serializer,
    recipientAddress,
    payload,
    senderCertificate,
    messageId,
    creationDate,
    ttl,
    senderCertificateChain
) {
    /**
     * Decrypt and deserialize payload.
     *
     * @throws EnvelopedDataException if the CMS EnvelopedData value is invalid or the
     *      `privateKey` is invalid.
     * @throws RAMFException if the plaintext is invalid.
     */
    @Throws(RAMFException::class, EnvelopedDataException::class)
    public fun unwrapPayload(privateKey: PrivateKey): P {
        val envelopedData = EnvelopedData.deserialize(payload) as SessionlessEnvelopedData
        val plaintext = envelopedData.decrypt(privateKey)
        return deserializePayload(plaintext)
    }

    @Throws(RAMFException::class)
    internal abstract fun deserializePayload(payloadPlaintext: ByteArray): P

    public companion object {
        // Per the RAMF spec
        internal const val MAX_PAYLOAD_PLAINTEXT_LENGTH = 8_322_048
    }
}
