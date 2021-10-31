package tech.relaycorp.relaynet.keystores

import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.security.PrivateKey

data class IdentityKeyPair(val privateKey: PrivateKey, val certificate: Certificate)
