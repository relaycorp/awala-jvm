package tech.relaycorp.relaynet.wrappers.cms

import java.math.BigInteger
import java.security.PublicKey

data class OriginatorSessionKey(val keyId: BigInteger, val publicKey: PublicKey)
