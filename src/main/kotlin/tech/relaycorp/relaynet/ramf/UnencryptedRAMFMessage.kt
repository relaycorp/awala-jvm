package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.messages.payloads.UnencryptedPayload
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.time.ZonedDateTime

abstract class UnencryptedRAMFMessage<P : UnencryptedPayload> internal constructor(
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
    @Throws(RAMFException::class)
    abstract fun deserializePayload(): P
}
