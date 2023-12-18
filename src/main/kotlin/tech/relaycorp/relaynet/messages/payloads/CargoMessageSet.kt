package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.ramf.InvalidPayloadException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Cargo message set.
 */
class CargoMessageSet(val messages: Array<ByteArray>) : GatewayEncryptedPayload() {
    /**
     * Serialize cargo message set.
     */
    override fun serializePlaintext(): ByteArray {
        val items = messages.map { DEROctetString(it) }
        return ASN1Utils.serializeSequence(items)
    }

    /**
     * Return the encapsulated messages, classified by type.
     */
    fun classifyMessages(): Sequence<CargoMessage> = messages.asSequence().map { CargoMessage(it) }

    companion object {
        /**
         * Deserialize a cargo message set.
         */
        fun deserialize(serialization: ByteArray): CargoMessageSet {
            val items =
                try {
                    ASN1Utils.deserializeHomogeneousSequence<DEROctetString>(serialization)
                } catch (exc: ASN1Exception) {
                    throw InvalidPayloadException("Invalid CargoMessageSet", exc)
                }
            val messages = items.map { it.octets }
            return CargoMessageSet(messages.toTypedArray())
        }
    }
}
