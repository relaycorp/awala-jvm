package tech.relaycorp.relaynet.keystores

import java.security.PrivateKey
import tech.relaycorp.relaynet.wrappers.x509.Certificate

data class IdentityKeyPair(val privateKey: PrivateKey, val certificate: Certificate)
