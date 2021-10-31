package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.RelaynetException

class KeyStoreBackendException internal constructor(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
