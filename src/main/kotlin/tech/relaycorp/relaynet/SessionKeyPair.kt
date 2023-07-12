package tech.relaycorp.relaynet

import java.security.PrivateKey
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
