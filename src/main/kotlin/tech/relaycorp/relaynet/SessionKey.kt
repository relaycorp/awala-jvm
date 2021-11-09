package tech.relaycorp.relaynet

import java.security.PrivateKey
import java.security.PublicKey
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair
import tech.relaycorp.relaynet.wrappers.generateRandomOctets

data class SessionKeyPair(val sessionKey: SessionKey, val privateKey: PrivateKey) {
    companion object {
        fun generate(curve: ECDHCurve = ECDHCurve.P256): SessionKeyPair {
            val keyId = generateRandomOctets(8)
            val sessionKeyPair = generateECDHKeyPair(curve)
            return SessionKeyPair(
                SessionKey(keyId, sessionKeyPair.public),
                sessionKeyPair.private
            )
        }
    }
}

data class SessionKey(val keyId: ByteArray, val publicKey: PublicKey) {
    override fun equals(other: Any?): Boolean {
        if (other !is SessionKey) return false

        if (!keyId.contentEquals(other.keyId)) return false
        if (publicKey != other.publicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyId.contentHashCode()
        result = 31 * result + publicKey.hashCode()
        return result
    }
}