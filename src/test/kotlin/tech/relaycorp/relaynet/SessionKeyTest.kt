package tech.relaycorp.relaynet

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.wrappers.ECDH_CURVE_MAP
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair

class SessionKeyTest {
    @Nested
    inner class Equals {
        private val stubSessionKey = SessionKey.generate().sessionKey

        @Test
        fun `Null should not equal`() {
            assertFalse(stubSessionKey.equals(null))
        }

        @Test
        fun `Different class instance should not equal`() {
            assertFalse(stubSessionKey.equals("not a session key"))
        }

        @Test
        fun `Same object should equal`() {
            assertEquals(stubSessionKey, stubSessionKey)
        }

        @Test
        fun `Different key id should not equal`() {
            val differentKey = stubSessionKey.copy("different id".toByteArray())

            assertNotEquals(differentKey, stubSessionKey)
        }

        @Test
        fun `Different public key should not equal`() {
            val differentPublicKey = generateECDHKeyPair().public
            val differentKey = stubSessionKey.copy(publicKey = differentPublicKey)

            assertNotEquals(differentKey, stubSessionKey)
        }

        @Test
        fun `Same key id and public key should equal`() {
            assertEquals(stubSessionKey, stubSessionKey.copy())
        }
    }

    @Nested
    inner class HashCode {
        private val stubSessionKey = SessionKey.generate().sessionKey

        @Test
        fun `Different key ids should produce different hash codes`() {
            assertNotEquals(
                stubSessionKey.copy("foo".toByteArray()).hashCode(),
                stubSessionKey.hashCode()
            )
        }

        @Test
        fun `Different public keys should produce different hash codes`() {
            val differentPublicKey = generateECDHKeyPair().public

            assertNotEquals(
                stubSessionKey.copy(publicKey = differentPublicKey).hashCode(),
                stubSessionKey.hashCode()
            )
        }

        @Test
        fun `Equivalent keys should produce the same hash codes`() {
            assertEquals(stubSessionKey, stubSessionKey.copy())
        }
    }

    @Nested
    inner class Generate {
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

        @Test
        fun `Key pair should use P-256 by default`() {
            val (sessionKey) = SessionKey.generate()

            assertEquals(
                "P-256",
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }

        @ParameterizedTest(name = "Key pair should use {0} if explicitly requested")
        @EnumSource
        fun explicitCurveName(curve: ECDHCurve) {
            val (sessionKey) = SessionKey.generate(curve)

            val curveName = ECDH_CURVE_MAP[curve]
            assertEquals(
                curveName,
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name
            )
        }
    }
}
