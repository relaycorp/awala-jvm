package tech.relaycorp.relaynet.pki

import tech.relaycorp.relaynet.RelaynetException

class CertificationPathException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
