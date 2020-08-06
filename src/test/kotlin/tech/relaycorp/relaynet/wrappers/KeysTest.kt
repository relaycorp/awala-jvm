package tech.relaycorp.relaynet.wrappers

import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.sha256Hex
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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
            val exception = assertThrows<KeyException> {
                generateRSAKeyPair(2047)
            }
            assertEquals(
                "Modulus should be at least 2048 (got 2047)",
                exception.message
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
    inner class PrivateAddress {
        @Test
        fun `Private node address should be calculated`() {
            val keyPair = generateRSAKeyPair()

            val privateAddress = keyPair.public.privateAddress

            assertEquals("0${sha256Hex(keyPair.public.encoded)}", privateAddress)
        }
    }
}
