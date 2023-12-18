package tech.relaycorp.relaynet

import kotlin.test.assertEquals
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import tech.relaycorp.relaynet.wrappers.ECDH_CURVE_MAP

class SessionKeyPairTest {
    @Nested
    inner class Generate {
        @Test
        fun `keyId should be randomly generated, 64-bit ByteArray`() {
            val (sessionKey) = SessionKeyPair.generate()

            assertEquals(8, sessionKey.keyId.size)
        }

        @Test
        fun `privateKey should correspond to public key`() {
            val sessionKeyGeneration = SessionKeyPair.generate()

            val ecPrivateKey = sessionKeyGeneration.privateKey as BCECPrivateKey
            val ecPublicKey = sessionKeyGeneration.sessionKey.publicKey as BCECPublicKey
            assertEquals(ecPrivateKey.parameters.g.multiply(ecPrivateKey.d), ecPublicKey.q)
            assertEquals(ecPrivateKey.params, ecPublicKey.params)
        }

        @Test
        fun `Key pair should use P-256 by default`() {
            val (sessionKey) = SessionKeyPair.generate()

            assertEquals(
                "P-256",
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name,
            )
        }

        @ParameterizedTest(name = "Key pair should use {0} if explicitly requested")
        @EnumSource
        fun explicitCurveName(curve: ECDHCurve) {
            val (sessionKey) = SessionKeyPair.generate(curve)

            val curveName = ECDH_CURVE_MAP[curve]
            assertEquals(
                curveName,
                ((sessionKey.publicKey as BCECPublicKey).params as ECNamedCurveSpec).name,
            )
        }
    }
}
