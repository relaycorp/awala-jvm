package tech.relaycorp.relaynet.wrappers

import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.ECDHCurve
import tech.relaycorp.relaynet.utils.sha256Hex

class KeysTest {
    @Nested
    inner class GenerateRSAKeyPair {
        @Test
        fun `Key pair should be returned when a valid modulus is passed`() {
            val keyPair = generateRSAKeyPair(4096)

            assert(keyPair.private is RSAPrivateKey)
            assertEquals(4096, (keyPair.private as RSAPrivateKey).modulus.bitLength())

            assert(keyPair.public is RSAPublicKey)
            assertEquals(4096, (keyPair.public as RSAPublicKey).modulus.bitLength())
        }

        @Test
        fun `Modulus should be 2048 by default`() {
            val keyPair = generateRSAKeyPair()

            assertEquals(2048, (keyPair.private as RSAPrivateKey).modulus.bitLength())

            assertEquals(2048, (keyPair.public as RSAPublicKey).modulus.bitLength())
        }

        @Test
        fun `Modulus should be 2048 or greater`() {
            val exception =
                assertThrows<KeyException> {
                    generateRSAKeyPair(2047)
                }
            assertEquals(
                "Modulus should be at least 2048 (got 2047)",
                exception.message,
            )
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()

            assertTrue(keyPair.public is BCRSAPublicKey)
            assertTrue(keyPair.private is BCRSAPrivateKey)
        }
    }

    @Nested
    inner class DeserializeRSAKeyPair {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<KeyException> { "s".toByteArray().deserializeRSAKeyPair() }

            assertEquals("Value is not a valid RSA private key", exception.message)
            assertTrue(exception.cause is InvalidKeySpecException)
        }

        @Test
        fun `Deserialize valid private key`() {
            val keyPair = generateRSAKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeRSAKeyPair()

            assertEquals(
                keyPair.private.encoded.asList(),
                keyPairDeserialized.private.encoded.asList(),
            )
            assertEquals(
                keyPair.public.encoded.asList(),
                keyPairDeserialized.public.encoded.asList(),
            )
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeRSAKeyPair()

            assertTrue(keyPairDeserialized.public is BCRSAPublicKey)
            assertTrue(keyPairDeserialized.private is BCRSAPrivateKey)
        }
    }

    @Nested
    inner class DeserializeRSAPublicKey {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<KeyException> { "s".toByteArray().deserializeRSAPublicKey() }

            assertEquals("Value is not a valid RSA public key", exception.message)
            assertTrue(exception.cause is InvalidKeySpecException)
        }

        @Test
        fun `Deserialize valid key`() {
            val keyPair = generateRSAKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeRSAPublicKey()

            assertEquals(publicKeySerialized.asList(), publicKeyDeserialized.encoded.asList())
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateRSAKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeRSAPublicKey()

            assertTrue(publicKeyDeserialized is BCRSAPublicKey)
        }
    }

    @Nested
    inner class DeserializeECKeyPair {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<KeyException> { "s".toByteArray().deserializeECKeyPair() }

            assertEquals("Value is not a valid EC private key", exception.message)
            assertTrue(exception.cause is InvalidKeySpecException)
        }

        @Test
        fun `Deserialize valid private key`() {
            val keyPair = generateECDHKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeECKeyPair()

            assertEquals(
                keyPair.private.encoded.asList(),
                keyPairDeserialized.private.encoded.asList(),
            )
            assertEquals(
                keyPair.public.encoded.asList(),
                keyPairDeserialized.public.encoded.asList(),
            )
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateECDHKeyPair()
            val privateKeySerialized = keyPair.private.encoded

            val keyPairDeserialized = privateKeySerialized.deserializeECKeyPair()

            assertTrue(keyPairDeserialized.public is ECPublicKey)
            assertTrue(keyPairDeserialized.private is ECPrivateKey)
        }
    }

    @Nested
    inner class DeserializeECPublicKey {
        @Test
        fun `Deserialize invalid key`() {
            val exception =
                assertThrows<KeyException> { "s".toByteArray().deserializeECPublicKey() }

            assertEquals("Value is not a valid EC public key", exception.message)
            assertTrue(exception.cause is InvalidKeySpecException)
        }

        @Test
        fun `Deserialize valid key`() {
            val keyPair = generateECDHKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeECPublicKey()

            assertEquals(publicKeySerialized.asList(), publicKeyDeserialized.encoded.asList())
        }

        @Test
        fun `BouncyCastle provider should be used`() {
            val keyPair = generateECDHKeyPair()
            val publicKeySerialized = keyPair.public.encoded

            val publicKeyDeserialized = publicKeySerialized.deserializeECPublicKey()

            assertTrue(publicKeyDeserialized is ECPublicKey)
        }
    }

    @Nested
    inner class GenerateECDHKeyPair {
        @Test
        fun `NIST P-256 curve should be used by default`() {
            val keyPair = generateECDHKeyPair()

            assertPrivateKeyCurveEquals("P-256", keyPair.private)
            assertPublicKeyCurveEquals("P-256", keyPair.public)
        }

        @Test
        fun `NIST P-384 should be supported`() {
            val keyPair = generateECDHKeyPair(ECDHCurve.P384)

            assertPrivateKeyCurveEquals("P-384", keyPair.private)
            assertPublicKeyCurveEquals("P-384", keyPair.public)
        }

        @Test
        fun `NIST P-521 should be supported`() {
            val keyPair = generateECDHKeyPair(ECDHCurve.P521)

            assertPrivateKeyCurveEquals("P-521", keyPair.private)
            assertPublicKeyCurveEquals("P-521", keyPair.public)
        }

        private fun assertPrivateKeyCurveEquals(
            curveName: String,
            privateKey: PrivateKey,
        ) {
            assertTrue(privateKey is ECPrivateKey)
            assertEquals("EC", privateKey.algorithm)
            assertEquals(curveName, (privateKey.params as ECNamedCurveSpec).name)
        }

        private fun assertPublicKeyCurveEquals(
            curveName: String,
            publicKey: PublicKey,
        ) {
            assertTrue(publicKey is ECPublicKey)
            assertEquals("EC", publicKey.algorithm)
            assertEquals(curveName, (publicKey.params as ECNamedCurveSpec).name)
        }
    }

    @Nested
    inner class NodeId {
        @Test
        fun `Private node address should be calculated from public key`() {
            val keyPair = generateRSAKeyPair()

            assertEquals("0${sha256Hex(keyPair.public.encoded)}", keyPair.public.nodeId)
        }

        @Test
        fun `Private node address should be calculated from private key`() {
            val keyPair = generateRSAKeyPair()

            assertEquals("0${sha256Hex(keyPair.public.encoded)}", keyPair.private.nodeId)
        }
    }
}
