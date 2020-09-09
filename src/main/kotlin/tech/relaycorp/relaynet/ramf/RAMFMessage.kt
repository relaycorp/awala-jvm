package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.payloads.Payload
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import java.net.MalformedURLException
import java.net.URL
import java.security.PrivateKey
import java.time.ZoneId
import java.time.ZoneOffset.UTC
import java.time.ZonedDateTime
import java.util.UUID

private const val MAX_RECIPIENT_ADDRESS_LENGTH = 1024
private const val MAX_MESSAGE_ID_LENGTH = 64
private const val MAX_TTL = 15552000

private const val DEFAULT_TTL_MINUTES = 5
private const val DEFAULT_TTL_SECONDS = DEFAULT_TTL_MINUTES * 60

internal typealias RAMFMessageConstructor<M> =
    (String, ByteArray, Certificate, String?, ZonedDateTime?, Int?, Set<Certificate>?) -> M

private val PRIVATE_ADDRESS_REGEX = "^0[a-f0-9]+$".toRegex()

/**
 * RAMF v1 message.
 *
 * @property recipientAddress The private or public address of the recipient
 * @property payload The payload
 * @property senderCertificate The sender's Relaynet PKI certificate
 */
abstract class RAMFMessage<P : Payload> internal constructor(
    private val serializer: RAMFSerializer,
    val recipientAddress: String,
    val payload: ByteArray,
    val senderCertificate: Certificate,
    id: String?,
    creationDate: ZonedDateTime?,
    ttl: Int?,
    senderCertificateChain: Set<Certificate>?
) {
    /**
     * The id of the message
     */
    val id = id ?: UUID.randomUUID().toString()

    /**
     * The creation date of the message
     */
    val creationDate: ZonedDateTime = creationDate ?: ZonedDateTime.now(ZoneId.of("UTC"))

    /**
     * The time-to-live of the message (in seconds)
     */
    val ttl = ttl ?: DEFAULT_TTL_SECONDS

    /**
     * Certificate chain of the sender
     */
    val senderCertificateChain = senderCertificateChain ?: setOf()

    /**
     * Expiry date of the message
     */
    val expiryDate: ZonedDateTime get() = creationDate.plusSeconds(ttl.toLong())

    /**
     * Report whether the recipient address is private
     */
    val isRecipientAddressPrivate get() = !recipientAddress.contains(":")

    init {
        if (MAX_RECIPIENT_ADDRESS_LENGTH < recipientAddress.length) {
            throw RAMFException(
                "Recipient address cannot span more than $MAX_RECIPIENT_ADDRESS_LENGTH octets " +
                    "(got ${recipientAddress.length})"
            )
        }
        if (MAX_MESSAGE_ID_LENGTH < this.id.length) {
            throw RAMFException(
                "Message id cannot span more than $MAX_MESSAGE_ID_LENGTH octets " +
                    "(got ${this.id.length})"
            )
        }
        if (this.ttl < 0) {
            throw RAMFException("TTL cannot be negative (got ${this.ttl})")
        }
        if (MAX_TTL < this.ttl) {
            throw RAMFException(
                "TTL cannot be greater than $MAX_TTL (got ${this.ttl})"
            )
        }
        if (MAX_PAYLOAD_LENGTH < payload.size) {
            throw RAMFException(
                "Payload cannot span more than $MAX_PAYLOAD_LENGTH octets (got ${payload.size})"
            )
        }
    }

    /**
     * Serialize the message.
     *
     * @param senderPrivateKey The private key to sign the message
     * @param hashingAlgorithm The hashing algorithm to use in the signature
     */
    fun serialize(
        senderPrivateKey: PrivateKey,
        hashingAlgorithm: HashingAlgorithm? = null
    ): ByteArray {
        return this.serializer.serialize(this, senderPrivateKey, hashingAlgorithm)
    }

    @Throws(InvalidMessageException::class)
    fun getSenderCertificationPath(trustedCAs: Collection<Certificate>) =
        senderCertificate.getCertificationPath(senderCertificateChain.toSet(), trustedCAs)

    /**
     * Validate the message.
     *
     * Passing a collection of [trustedCAs] will also verify:
     *
     * - That there's a valid path between the sender's certificate and one of the [trustedCAs].
     * - That, if the recipient address is private, the sender's issuer is the recipient itself.
     *
     * If there are no trusted CAs, avoid setting [trustedCAs] to an empty collection as that will
     * always cause validation to fail. This is intentional: We won't try to guess whether you made
     * a mistake or really meant to skip authorization checks.
     *
     * @param requiredRecipientAddressType The type of recipient address this message must have, if you
     *    need to enforce a specific type
     * @param trustedCAs The trusted CAs (if any); an empty set will always fail validation
     * @throws RAMFException If the message was never (or is no longer) valid
     */
    @Throws(RAMFException::class, InvalidMessageException::class)
    fun validate(
        requiredRecipientAddressType: RecipientAddressType?,
        trustedCAs: Collection<Certificate>? = null
    ) {
        validateTiming()

        validateRecipientAddress(requiredRecipientAddressType)

        try {
            senderCertificate.validate()
        } catch (exc: CertificateException) {
            throw RAMFException("Invalid sender certificate", exc)
        }

        if (trustedCAs != null) {
            validateAuthorization(trustedCAs, isRecipientAddressPrivate)
        }
    }

    private fun validateTiming() {
        val now = ZonedDateTime.now(UTC)
        if (now < creationDate) {
            throw RAMFException("Creation date is in the future")
        }
        if (creationDate < senderCertificate.startDate) {
            throw RAMFException("Message was created before sender certificate was valid")
        }
        if (expiryDate < now) {
            throw RAMFException("Message already expired")
        }

        // We're already validating the sender's certificate separately, so we don't need to check
        // whether the expiry date of the message is after the expiry date of the sender's
        // certificate: We don't care if that's the case, we just care that neither the message nor
        // the sender's certificate has expired.
    }

    private fun validateRecipientAddress(requiredRecipientAddressType: RecipientAddressType?) {
        val isPublic = try {
            URL(recipientAddress)
            true
        } catch (e: MalformedURLException) {
            false
        }
        if (!isPublic && !PRIVATE_ADDRESS_REGEX.matches(recipientAddress)) {
            throw RAMFException("Recipient address is an invalid private address")
        }

        val addressType = if (isRecipientAddressPrivate)
            RecipientAddressType.PRIVATE
        else
            RecipientAddressType.PUBLIC
        if (requiredRecipientAddressType != null && requiredRecipientAddressType != addressType) {
            throw InvalidMessageException("Invalid recipient address type")
        }
    }

    @Throws(InvalidMessageException::class)
    private fun validateAuthorization(
        trustedCAs: Collection<Certificate>,
        isRecipientAddressPrivate: Boolean
    ) {
        val certificationPath = try {
            getSenderCertificationPath(trustedCAs)
        } catch (exc: CertificateException) {
            throw InvalidMessageException("Sender is not trusted", exc)
        }

        if (isRecipientAddressPrivate) {
            val recipientCertificate = certificationPath[1]
            val recipientPrivateAddress = recipientCertificate.subjectPrivateAddress
            if (recipientPrivateAddress != recipientAddress) {
                throw InvalidMessageException("Sender is authorized by the wrong recipient")
            }
        }
    }

    companion object {
        internal const val MAX_PAYLOAD_LENGTH = 8_388_608
    }
}
