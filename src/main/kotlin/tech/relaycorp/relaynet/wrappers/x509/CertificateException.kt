package tech.relaycorp.relaynet.wrappers.x509

import tech.relaycorp.relaynet.RelaynetException

/**
 * Relaynet PKI certificate exception.
 */
public class CertificateException(message: String, cause: Throwable? = null) :
    RelaynetException(message, cause)
