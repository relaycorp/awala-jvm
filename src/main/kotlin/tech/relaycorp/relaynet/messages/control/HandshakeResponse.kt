package tech.relaycorp.relaynet.messages.control

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class HandshakeResponse(val nonceSignatures: List<ByteArray>) {
    fun serialize(): ByteArray {
        val nonceSignaturesASN1 = ASN1EncodableVector(nonceSignatures.size)
        nonceSignatures.forEach { nonceSignaturesASN1.add(DEROctetString(it)) }
        return ASN1Utils.serializeSequence(listOf(DERSequence(nonceSignaturesASN1)), false)
    }

    companion object {
        fun deserialize(serialization: ByteArray): HandshakeResponse {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidMessageException("Handshake response is not a DER sequence", exc)
            }
            if (sequence.isEmpty()) {
                throw InvalidMessageException(
                    "Handshake response sequence should have at least 1 item"
                )
            }
            val nonceSignaturesASN1 = DERSequence.getInstance(sequence.first(), false)
            val nonceSignatures = nonceSignaturesASN1.objects.asSequence()
                .map { DEROctetString.getInstance(it).octets }.toList()
            return HandshakeResponse(nonceSignatures)
        }
    }
}
