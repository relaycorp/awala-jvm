package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Cargo message set.
 */
class CargoMessageSet(val messages: Array<ByteArray>) : EncryptedPayload() {
    /**
     * Serialize cargo message set.
     */
    override fun serializePlaintext(): ByteArray {
        val items = messages.map { DEROctetString(it) as ASN1Encodable }.toTypedArray()
        return ASN1Utils.serializeSequence(items, false)
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
            val items = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw RAMFException("Invalid CargoMessageSet", exc)
            }
            val messages = items.map { ASN1Utils.getOctetString(it).octets }
            return CargoMessageSet(messages.toTypedArray())
        }
    }
}
