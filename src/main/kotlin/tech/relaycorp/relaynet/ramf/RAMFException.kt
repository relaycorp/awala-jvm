package tech.relaycorp.relaynet.ramf

import tech.relaycorp.relaynet.RelaynetException

/**
 * RAMF-related exception
 */
public class RAMFException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
