package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

/**
 * Cargo message set.
 */
public class CargoMessageSet(public val messages: Array<ByteArray>) : EncryptedPayload() {
    /**
     * Serialize cargo message set.
     */
    override fun serializePlaintext(): ByteArray {
        val items = messages.map { DEROctetString(it) as ASN1Encodable }.toTypedArray()
        return ASN1Utils.serializeSequence(items)
    }

    /**
     * Return the encapsulated messages, classified by type.
     */
    public fun classifyMessages(): Sequence<CargoMessage> =
        messages.asSequence().map { CargoMessage(it) }

    public companion object {
        /**
         * Deserialize a cargo message set.
         */
        public fun deserialize(serialization: ByteArray): CargoMessageSet {
            val items = try {
                ASN1Utils.deserializeSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw RAMFException("Invalid CargoMessageSet", exc)
            }
            items.forEach {
                if (it !is DEROctetString) {
                    throw RAMFException("At least one message is not an OCTET STRING")
                }
            }
            val messages = items.map { (it as DEROctetString).octets }
            return CargoMessageSet(messages.toTypedArray())
        }
    }
}
