package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class HandshakeChallenge(val nonce: ByteArray) {
    fun serialize(): ByteArray = ASN1Utils.serializeSequence(
        arrayOf(DEROctetString(nonce)),
        false
    )

    companion object {
        fun deserialize(serialization: ByteArray): HandshakeChallenge {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Handshake challenge is not a DER sequence", exc)
            }
            if (sequence.isEmpty()) {
                throw InvalidMessageException(
                    "Handshake challenge sequence should have at least 1 item"
                )
            }
            val nonceASN1 = ASN1Utils.getVisibleString(sequence[0])
            return HandshakeChallenge(nonceASN1.octets)
        }
    }
}
