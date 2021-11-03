package tech.relaycorp.relaynet.ramf

class InvalidPayloadException(message: String, cause: Throwable? = null) :
    RAMFException(message, cause)
