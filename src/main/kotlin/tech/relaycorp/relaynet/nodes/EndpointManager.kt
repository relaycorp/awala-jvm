package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.messages.payloads.ServiceMessage

class EndpointManager(
    privateKeyStore: PrivateKeyStore,
    sessionPublicKeyStore: SessionPublicKeyStore,
    cryptoOptions: NodeCryptoOptions = NodeCryptoOptions(),
) : NodeManager<ServiceMessage>(privateKeyStore, sessionPublicKeyStore, cryptoOptions)
