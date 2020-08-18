package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.RelaynetException

public class InvalidMessageException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
