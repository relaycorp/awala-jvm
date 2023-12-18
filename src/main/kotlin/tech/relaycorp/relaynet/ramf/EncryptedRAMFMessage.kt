package tech.relaycorp.relaynet.ramf

import java.security.PrivateKey
import java.time.ZonedDateTime
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.messages.Recipient
import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload
import tech.relaycorp.relaynet.messages.payloads.PayloadUnwrapping
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedDataException
import tech.relaycorp.relaynet.wrappers.cms.SessionEnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class EncryptedRAMFMessage<P : EncryptedPayload> internal constructor(
    serializer: RAMFSerializer,
    recipient: Recipient,
    payload: ByteArray,
    senderCertificate: Certificate,
    messageId: String?,
    creationDate: ZonedDateTime?,
    ttl: Int?,
    senderCertificateChain: Set<Certificate>?,
) : RAMFMessage<P>(
        serializer,
        recipient,
        payload,
        senderCertificate,
        messageId,
        creationDate,
        ttl,
        senderCertificateChain,
    ) {
    /**
     * Decrypt and deserialize payload.
     *
     * @throws EnvelopedDataException if the CMS EnvelopedData value is invalid or the
     *      `privateKey` is invalid.
     * @throws MissingKeyException if the session key doesn't exist.
     * @throws InvalidPayloadException if the plaintext is invalid.
     * @throws NotImplementedError if the recipient address is public.
     */
    @Throws(
        InvalidPayloadException::class,
        MissingKeyException::class,
        EnvelopedDataException::class,
        NotImplementedError::class,
    )
    suspend fun unwrapPayload(privateKeyStore: PrivateKeyStore): PayloadUnwrapping<P> {
        val envelopedData = deserializeEnvelopedData()
        val keyId = envelopedData.getRecipientKeyId()
        val privateKey =
            privateKeyStore.retrieveSessionKey(
                keyId.id,
                recipient.id,
                senderCertificate.subjectId,
            )
        return unwrapEnvelopedData(envelopedData, privateKey)
    }

    /**
     * Decrypt and deserialize payload.
     *
     * @throws EnvelopedDataException if the CMS EnvelopedData value is invalid or the
     *      `privateKey` is invalid.
     * @throws InvalidPayloadException if the plaintext is invalid.
     */
    @Throws(InvalidPayloadException::class, EnvelopedDataException::class)
    fun unwrapPayload(privateKey: PrivateKey): PayloadUnwrapping<P> {
        val envelopedData = deserializeEnvelopedData()
        return unwrapEnvelopedData(envelopedData, privateKey)
    }

    private fun unwrapEnvelopedData(
        envelopedData: SessionEnvelopedData,
        privateKey: PrivateKey,
    ): PayloadUnwrapping<P> {
        val plaintext = envelopedData.decrypt(privateKey)
        val payload = deserializePayload(plaintext)
        return PayloadUnwrapping(payload, envelopedData.getOriginatorKey())
    }

    @Throws(InvalidPayloadException::class)
    protected abstract fun deserializePayload(payloadPlaintext: ByteArray): P

    private fun deserializeEnvelopedData(): SessionEnvelopedData {
        val envelopedData = EnvelopedData.deserialize(payload)
        if (envelopedData !is SessionEnvelopedData) {
            throw InvalidPayloadException("SessionlessEnvelopedData is no longer supported")
        }
        return envelopedData
    }

    companion object {
        // Per the RAMF spec
        internal const val MAX_PAYLOAD_PLAINTEXT_LENGTH = 8_322_048
    }
}
