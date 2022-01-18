package tech.relaycorp.relaynet.keystores

sealed class PrivateKeyData(val privateKeyDer: ByteArray)

class IdentityPrivateKeyData(
    privateKeyDer: ByteArray,
    val certificatesDer: List<ByteArray>,
) : PrivateKeyData(privateKeyDer)
