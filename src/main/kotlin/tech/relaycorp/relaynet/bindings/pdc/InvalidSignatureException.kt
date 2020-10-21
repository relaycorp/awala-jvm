package tech.relaycorp.relaynet.bindings.pdc

import tech.relaycorp.relaynet.RelaynetException

class InvalidSignatureException(message: String, cause: Throwable) :
    RelaynetException(message, cause)
