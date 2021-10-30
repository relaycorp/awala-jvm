package tech.relaycorp.relaynet

class InvalidNodeConnectionParams(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
