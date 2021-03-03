package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class ServiceMessage(val type: String, val content: ByteArray) : EncryptedPayload() {
    override fun serializePlaintext(): ByteArray {
        val typeASN1 = DERVisibleString(type)
        val contentASN1 = DEROctetString(content)
        return ASN1Utils.serializeSequence(arrayOf(typeASN1, contentASN1), false)
    }

    companion object {
        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): ServiceMessage {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Service message is not a DER sequence", exc)
            }
            if (sequence.size < 2) {
                throw InvalidMessageException(
                    "Service message sequence should have at least two items (got ${sequence.size})"
                )
            }
            val type = ASN1Utils.getVisibleString(sequence.first())
            val content = ASN1Utils.getOctetString(sequence[1])
            return ServiceMessage(type.string, content.octets)
        }
    }
}
