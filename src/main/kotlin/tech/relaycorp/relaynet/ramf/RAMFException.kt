package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.RelaynetException

/**
 * RAMF-related issue.
 */
open class RAMFException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
