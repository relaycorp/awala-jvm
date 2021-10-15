package tech.relaycorp.relaynet.wrappers.cms

import java.security.PublicKey

data class OriginatorSessionKey(val keyId: ByteArray, val publicKey: PublicKey)
