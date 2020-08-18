package tech.relaycorp.relaynet

/**
 * Base class for all exceptions in this library
 */
public abstract class RelaynetException(message: String, cause: Throwable?) :
    Exception(message, cause)
