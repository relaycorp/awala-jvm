package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.keystores.PrivateKeyStore
import tech.relaycorp.relaynet.keystores.SessionPublicKeyStore
import tech.relaycorp.relaynet.utils.StubEncryptedPayload

class StubNodeManager(
    privateKeyStore: PrivateKeyStore,
    sessionPublicKeyStore: SessionPublicKeyStore,
    cryptoOptions: NodeCryptoOptions = NodeCryptoOptions(),
) : NodeManager<StubEncryptedPayload>(privateKeyStore, sessionPublicKeyStore, cryptoOptions)
