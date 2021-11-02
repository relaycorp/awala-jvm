package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.keystores.PrivateKeyStore

class StubNodeManager(
    privateKeyStore: PrivateKeyStore,
    cryptoOptions: NodeCryptoOptions? = null,
) : NodeManager(privateKeyStore, cryptoOptions)
