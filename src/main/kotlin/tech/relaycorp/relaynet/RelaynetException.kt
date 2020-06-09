package tech.relaycorp.relaynet

/**
 * Base class for all exceptions in this library
 */
abstract class RelaynetException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
