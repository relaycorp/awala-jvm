package tech.relaycorp.relaynet.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import tech.relaycorp.relaynet.BC_PROVIDER

/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */
internal object RSASigning {
    fun sign(
        plaintext: ByteArray,
        privateKey: PrivateKey,
    ): ByteArray {
        val signature = makeSignature()
        signature.initSign(privateKey)
        signature.update(plaintext)
        return signature.sign()
    }

    fun verify(
        ciphertext: ByteArray,
        publicKey: PublicKey,
        expectedPlaintext: ByteArray,
    ): Boolean {
        val signature = makeSignature()
        signature.initVerify(publicKey)
        signature.update(expectedPlaintext)
        return signature.verify(ciphertext)
    }

    private fun makeSignature() = Signature.getInstance("SHA256withRSAandMGF1", BC_PROVIDER)
}
