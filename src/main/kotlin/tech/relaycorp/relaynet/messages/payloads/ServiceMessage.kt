package tech.relaycorp.relaynet.messages.payloads

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class ServiceMessage(val type: String, val content: ByteArray) : EncryptedPayload() {
    override fun serializePlaintext(): ByteArray {
        val typeASN1 = DERVisibleString(type)
        val contentASN1 = DEROctetString(content)
        return ASN1Utils.serializeSequence(arrayOf(typeASN1, contentASN1), false)
    }
}
