package tech.relaycorp.relaynet

import java.security.PublicKey
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey

data class SessionKey(val keyId: ByteArray, val publicKey: PublicKey) {
    override fun equals(other: Any?): Boolean {
        if (other !is SessionKey) return false

        if (!keyId.contentEquals(other.keyId)) return false

        return publicKey == other.publicKey
    }

    override fun hashCode(): Int {
        var result = keyId.contentHashCode()
        result = 31 * result + publicKey.hashCode()
        return result
    }

    internal fun encode(): DERSequence = ASN1Utils.makeSequence(
        listOf(
            DEROctetString(keyId),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded)
        ),
        false
    )

    internal companion object {
        @Throws(SessionKeyException::class)
        fun decode(encoding: ASN1TaggedObject): SessionKey {
            val sequence = try {
                DERSequence.getInstance(encoding, false)
            } catch (exc: IllegalStateException) {
                throw SessionKeyException(
                    "Session key should be an implicitly-tagged SEQUENCE",
                    exc
                )
            }
            if (sequence.size() != 2) {
                throw SessionKeyException("Session key should have at least two items")
            }

            val keyId = decodeKeyId(sequence)
            val publicKey = decodePublicKey(sequence)
            return SessionKey(keyId, publicKey)
        }

        private fun decodePublicKey(sequence: ASN1Sequence): PublicKey {
            val publicKeyAsn1 = sequence.getObjectAt(1)
            if (publicKeyAsn1 !is ASN1TaggedObject) {
                throw SessionKeyException("Public key should be implicitly tagged")
            }
            val publicKeySki = try {
                SubjectPublicKeyInfo.getInstance(publicKeyAsn1, false)
            } catch (exc: IllegalStateException) {
                throw SessionKeyException("Public key should be a SubjectPublicKeyInfo", exc)
            }
            return publicKeySki.encoded.deserializeECPublicKey()
        }

        private fun decodeKeyId(sequence: ASN1Sequence): ByteArray {
            val keyIdAsn1 = sequence.getObjectAt(0)
            if (keyIdAsn1 !is ASN1TaggedObject) {
                throw SessionKeyException("Session key id should be implicitly tagged")
            }
            val keyId = try {
                ASN1Utils.getOctetString(keyIdAsn1).octets
            } catch (exc: IllegalStateException) {
                throw SessionKeyException("Session key id should be an OCTET STRING", exc)
            }
            return keyId
        }
    }
}
