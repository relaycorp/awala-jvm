package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID

private const val MAX_RECIPIENT_ADDRESS_LENGTH = 1024
private const val MAX_MESSAGE_ID_LENGTH = 64
private const val MAX_TTL = 15552000
private const val MAX_PAYLOAD_LENGTH = 8388608

private const val DEFAULT_TTL_MINUTES = 5
private const val DEFAULT_TTL_SECONDS = DEFAULT_TTL_MINUTES * 60

typealias RAMFMessageConstructor<M> =
        (String, ByteArray, Certificate, String?, ZonedDateTime?, Int?, Set<Certificate>?) -> M

abstract class RAMFMessage(
    private val serializer: RAMFSerializer,
    val recipientAddress: String,
    val payload: ByteArray,
    val senderCertificate: Certificate,
    id: String?,
    creationDate: ZonedDateTime?,
    ttl: Int?,
    senderCertificateChain: Set<Certificate>?
) {
    val id = id ?: UUID.randomUUID().toString()
    val creationDate: ZonedDateTime = creationDate ?: ZonedDateTime.now(ZoneId.of("UTC"))
    val ttl = ttl ?: DEFAULT_TTL_SECONDS
    val senderCertificateChain = senderCertificateChain ?: setOf()

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

    fun serialize(
        senderPrivateKey: PrivateKey,
        hashingAlgorithm: HashingAlgorithm? = null
    ): ByteArray {
        return this.serializer.serialize(this, senderPrivateKey, hashingAlgorithm)
    }
}
