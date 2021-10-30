package tech.relaycorp.relaynet

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SessionKeyTest {
    @RepeatedTest(8) // Because the bitLength of the value is variable
    fun `keyId should be randomly generated, 64-bit BigInteger`() {
        val (sessionKey) = SessionKey.generate()

        assertTrue(sessionKey.keyId.bitLength() in 48..64)
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
