package tech.relaycorp.relaynet.bindings.pdc

import tech.relaycorp.relaynet.RelaynetException

sealed class PDCException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)

/**
 * Base class for connectivity errors and errors caused by the server.
 */
abstract class ServerException internal constructor(message: String, cause: Throwable?) :
    PDCException(message, cause)

/**
 * Error before or while connected to the server.
 *
 * The client should retry later.
 */
class ServerConnectionException(message: String, cause: Throwable? = null) :
    ServerException(message, cause)

/**
 * The server sent an invalid message or behaved in any other way that violates the binding.
 *
 * Retrying later is unlikely to make a difference in the short term.
 */
class ServerBindingException(message: String, cause: Throwable? = null) :
    ServerException(message, cause)

/**
 * The server claims that the client is violating the binding.
 *
 * Retrying later is unlikely to make a difference.
 */
class ClientBindingException(message: String) : PDCException(message)

/**
 * The server refused to accept a parcel due to reasons outside the control of the client.
 *
 * For example, the sender of the parcel may be untrusted.
 */
class RejectedParcelException(message: String) : PDCException(message)

/**
 * The user of the client made a mistake while specifying the nonce signer(s).
 */
class NonceSignerException(message: String) : PDCException(message)
