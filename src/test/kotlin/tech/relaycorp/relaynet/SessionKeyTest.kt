package tech.relaycorp.relaynet

import kotlin.test.assertEquals
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.junit.jupiter.api.Test

class SessionKeyTest {
    @Test
    fun `keyId should be randomly generated, 64-bit ByteArray`() {
        val (sessionKey) = SessionKey.generate()

        assertEquals(8, sessionKey.keyId.size)
    }

    @Test
    fun `privateKey should correspond to public key`() {
        val sessionKeyGeneration = SessionKey.generate()

        val ecPrivateKey = sessionKeyGeneration.privateKey as BCECPrivateKey
        val ecPublicKey = sessionKeyGeneration.sessionKey.publicKey as BCECPublicKey
        assertEquals(ecPrivateKey.parameters.g.multiply(ecPrivateKey.d), ecPublicKey.q)
        assertEquals(ecPrivateKey.params, ecPublicKey.params)
    }
}
