package tech.relaycorp.relaynet.bindings.pdc

import tech.relaycorp.relaynet.messages.control.NonceSignature
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.net.URI
import java.net.http.HttpRequest
import java.security.PrivateKey

/**
 * Handshake nonce signer for a given private endpoint or private gateway.
 *
 * @param certificate The certificate of the private node
 * @param privateKey The private key of the private node
 */
class NonceSigner(val certificate: Certificate, private val privateKey: PrivateKey) {
    fun sign(nonce: ByteArray): ByteArray {
        val signature = NonceSignature(nonce, certificate)
        return signature.serialize(privateKey)
    }

    fun thingy() = HttpRequest.newBuilder()
        .uri(URI("https://postman-echo.com/get"))
        .GET()
        .build()
}
