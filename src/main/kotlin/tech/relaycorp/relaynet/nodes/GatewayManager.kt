package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.messages.payloads.GatewayEncryptedPayload

class GatewayManager(
    privateKeyStore: PrivateKeyStore,
    sessionPublicKeyStore: SessionPublicKeyStore,
    cryptoOptions: NodeCryptoOptions = NodeCryptoOptions(),
) : NodeManager<GatewayEncryptedPayload> (privateKeyStore, sessionPublicKeyStore, cryptoOptions)
