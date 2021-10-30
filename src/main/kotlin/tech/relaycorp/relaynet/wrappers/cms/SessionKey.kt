package tech.relaycorp.relaynet.wrappers.cms

import java.math.BigInteger
import java.security.PublicKey

data class SessionKey(val keyId: BigInteger, val publicKey: PublicKey)
