package tech.relaycorp.relaynet.wrappers.cms

import tech.relaycorp.relaynet.RelaynetException

class EnvelopedDataException internal constructor(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
