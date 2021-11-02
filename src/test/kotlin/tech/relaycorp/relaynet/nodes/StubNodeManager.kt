package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore

class StubNodeManager(
    privateKeyStore: PrivateKeyStore,
    sessionPublicKeyStore: SessionPublicKeyStore,
    cryptoOptions: NodeCryptoOptions? = null,
) : NodeManager(privateKeyStore, sessionPublicKeyStore, cryptoOptions)
