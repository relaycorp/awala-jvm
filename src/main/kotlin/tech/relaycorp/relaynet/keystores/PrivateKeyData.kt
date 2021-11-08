package tech.relaycorp.relaynet.keystores

sealed class PrivateKeyData(val privateKeyDer: ByteArray)

class IdentityPrivateKeyData(
    privateKeyDer: ByteArray,
    val certificateDer: ByteArray,
) : PrivateKeyData(privateKeyDer)
