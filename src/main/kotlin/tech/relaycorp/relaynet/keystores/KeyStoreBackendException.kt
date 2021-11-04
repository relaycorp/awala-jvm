package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.RelaynetException

open class KeyStoreBackendException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
