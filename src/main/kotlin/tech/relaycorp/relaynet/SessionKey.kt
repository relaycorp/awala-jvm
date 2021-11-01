package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair
import tech.relaycorp.relaynet.wrappers.generateRandomOctets
import java.security.PrivateKey
import java.security.PublicKey

data class SessionKeyGeneration(val sessionKey: SessionKey, val privateKey: PrivateKey)

data class SessionKey(val keyId: ByteArray, val publicKey: PublicKey) {
    companion object {
        fun generate(): SessionKeyGeneration {
            val keyId = generateRandomOctets(8)
            val sessionKeyPair = generateECDHKeyPair()
            return SessionKeyGeneration(
                SessionKey(keyId, sessionKeyPair.public),
                sessionKeyPair.private
            )
        }
    }
}
