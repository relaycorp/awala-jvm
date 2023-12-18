package tech.relaycorp.relaynet.bindings.pdc

import java.security.PrivateKey
import tech.relaycorp.relaynet.wrappers.x509.Certificate

/**
 * Object to produce detached signatures given a key pair.
 *
 * @param certificate The certificate of the private node
 * @param privateKey The private key of the private node
 */
class Signer(val certificate: Certificate, private val privateKey: PrivateKey) {
    fun sign(
        plaintext: ByteArray,
        detachedSignatureType: DetachedSignatureType,
    ): ByteArray {
        return detachedSignatureType.sign(plaintext, privateKey, certificate)
    }
}
