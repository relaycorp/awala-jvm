package tech.relaycorp.relaynet

abstract class RelaynetException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
