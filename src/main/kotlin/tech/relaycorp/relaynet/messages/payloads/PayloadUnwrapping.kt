package tech.relaycorp.relaynet.messages.payloads

import tech.relaycorp.relaynet.SessionKey

data class PayloadUnwrapping<P : EncryptedPayload>(
    val payload: P,
    val peerSessionKey: SessionKey,
)
