package tech.relaycorp.relaynet

import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair
import tech.relaycorp.relaynet.wrappers.generateRandomBigInteger
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey

data class SessionKeyGeneration(val sessionKey: SessionKey, val privateKey: PrivateKey)

data class SessionKey(val keyId: BigInteger, val publicKey: PublicKey) {
    companion object {
        fun generate(): SessionKeyGeneration {
            val keyId = generateRandomBigInteger()
            val sessionKeyPair = generateECDHKeyPair()
            return SessionKeyGeneration(
                SessionKey(keyId, sessionKeyPair.public),
                sessionKeyPair.private
            )
        }
    }
}
