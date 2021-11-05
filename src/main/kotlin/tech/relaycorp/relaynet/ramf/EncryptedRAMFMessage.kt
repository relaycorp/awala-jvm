package tech.relaycorp.relaynet.ramf

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.keystores.MissingKeyException
import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.messages.payloads.EncryptedPayload
import tech.relaycorp.relaynet.messages.payloads.PayloadUnwrapping
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedData
import tech.relaycorp.relaynet.wrappers.cms.EnvelopedDataException
import tech.relaycorp.relaynet.wrappers.cms.SessionEnvelopedData
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class EncryptedRAMFMessage<P : EncryptedPayload> internal constructor(
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
     * @throws MissingKeyException if the session key doesn't exist.
     * @throws InvalidPayloadException if the plaintext is invalid.
     * @throws NotImplementedError if the recipient address is public.
     */
    @Throws(
        InvalidPayloadException::class,
        MissingKeyException::class,
        EnvelopedDataException::class,
        NotImplementedError::class
    )
    suspend fun unwrapPayload(privateKeyStore: PrivateKeyStore): PayloadUnwrapping<P> {
        if (!isRecipientAddressPrivate) {
            // Fix is part of https://github.com/relaycorp/relayverse/issues/19
            TODO("Public recipients are not currently supported")
        }
        val envelopedData = EnvelopedData.deserialize(payload)
        if (envelopedData !is SessionEnvelopedData) {
            throw InvalidPayloadException("SessionlessEnvelopedData is no longer supported")
        }
        val keyId = envelopedData.getRecipientKeyId()
        val privateKey = privateKeyStore.retrieveSessionKey(
            keyId.id,
            recipientAddress,
            senderCertificate.subjectPrivateAddress
        )
        val plaintext = envelopedData.decrypt(privateKey)
        val payload = deserializePayload(plaintext)
        return PayloadUnwrapping(payload, envelopedData.getOriginatorKey())
    }

    @Throws(InvalidPayloadException::class)
    protected abstract fun deserializePayload(payloadPlaintext: ByteArray): P

    companion object {
        // Per the RAMF spec
        internal const val MAX_PAYLOAD_PLAINTEXT_LENGTH = 8_322_048
    }
}
