package tech.relaycorp.relaynet.crypto

import tech.relaycorp.relaynet.BC_PROVIDER
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

internal object RSASigning {
    fun sign(plaintext: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = makeSignature()
        signature.initSign(privateKey)
        signature.update(plaintext)
        return signature.sign()
    }

    fun verify(ciphertext: ByteArray, publicKey: PublicKey, expectedPlaintext: ByteArray): Boolean {
        val signature = makeSignature()
        signature.initVerify(publicKey)
        signature.update(expectedPlaintext)
        return signature.verify(ciphertext)
    }

    private fun makeSignature() = Signature.getInstance("SHA256withRSAandMGF1", BC_PROVIDER)
}
