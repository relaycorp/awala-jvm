package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.RelaynetException

class KeyStoreBackendException(message: String, cause: Throwable?) :
    RelaynetException(message, cause)
