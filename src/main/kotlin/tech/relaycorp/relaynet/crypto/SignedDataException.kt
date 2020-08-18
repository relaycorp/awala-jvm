package tech.relaycorp.relaynet.crypto

import tech.relaycorp.relaynet.RelaynetException

public class SignedDataException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
