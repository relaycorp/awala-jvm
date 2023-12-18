package tech.relaycorp.relaynet

import java.security.PublicKey
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.toExplicitlyTaggedObject
import tech.relaycorp.relaynet.utils.toImplicitlyTaggedObject
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.generateECDHKeyPair

class SessionKeyTest {
    val keyId = "foo".toByteArray()
    val publicKey: PublicKey = generateECDHKeyPair().public
    private val sessionKey = SessionKey(keyId, publicKey)

    @Nested
    inner class Equals {
        @Test
        fun `Null should not equal`() {
            assertFalse(sessionKey.equals(null))
        }

        @Test
        fun `Different class instance should not equal`() {
            assertFalse(sessionKey.equals("not a session key"))
        }

        @Test
        fun `Same object should equal`() {
            assertEquals(sessionKey, sessionKey)
        }

        @Test
        fun `Different key id should not equal`() {
            val differentKey = sessionKey.copy("different id".toByteArray())

            assertNotEquals(differentKey, sessionKey)
        }

        @Test
        fun `Different public key should not equal`() {
            val differentPublicKey = generateECDHKeyPair().public
            val differentKey = sessionKey.copy(publicKey = differentPublicKey)

            assertNotEquals(differentKey, sessionKey)
        }

        @Test
        fun `Same key id and public key should equal`() {
            assertEquals(sessionKey, sessionKey.copy())
        }
    }

    @Nested
    inner class HashCode {
        @Test
        fun `Different key ids should produce different hash codes`() {
            assertNotEquals(
                sessionKey.copy("bar".toByteArray()).hashCode(),
                sessionKey.hashCode(),
            )
        }

        @Test
        fun `Different public keys should produce different hash codes`() {
            val differentPublicKey = generateECDHKeyPair().public

            assertNotEquals(
                sessionKey.copy(publicKey = differentPublicKey).hashCode(),
                sessionKey.hashCode(),
            )
        }

        @Test
        fun `Equivalent keys should produce the same hash codes`() {
            assertEquals(sessionKey, sessionKey.copy())
        }
    }

    @Nested
    inner class Encode {
        @Test
        fun `Key id should be encoded`() {
            val encoding = sessionKey.encode()

            val keyIdASN1 =
                ASN1Utils.getOctetString(encoding.getObjectAt(0) as ASN1TaggedObject)
            assertEquals(sessionKey.keyId, keyIdASN1.octets)
        }

        @Test
        fun `Public key should be encoded`() {
            val encoding = sessionKey.encode()

            val publicKeyASN1 =
                SubjectPublicKeyInfo.getInstance(
                    encoding.getObjectAt(1) as ASN1TaggedObject,
                    false,
                )
            assertContentEquals(sessionKey.publicKey.encoded, publicKeyASN1.encoded)
        }
    }

    @Nested
    inner class Decode {
        @Test
        fun `Encoding should be implicitly tagged`() {
            val encoding = sessionKey.encode()

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toExplicitlyTaggedObject())
                }

            assertEquals(
                "Session key should be an implicitly-tagged SEQUENCE",
                exception.message,
            )
        }

        @Test
        fun `Encoding should be a SEQUENCE`() {
            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(DERNull.INSTANCE.toImplicitlyTaggedObject())
                }

            assertEquals(
                "Session key should be an implicitly-tagged SEQUENCE",
                exception.message,
            )
        }

        @Test
        fun `Encoding should have at least two items`() {
            val encoding = ASN1Utils.makeSequence(listOf(DEROctetString(keyId)))

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toImplicitlyTaggedObject())
                }

            assertEquals("Session key should have at least two items", exception.message)
        }

        @Test
        fun `Key id should be an OCTET STRING`() {
            val encoding =
                ASN1Utils.makeSequence(
                    listOf(
                        DERNull.INSTANCE,
                        SubjectPublicKeyInfo.getInstance(publicKey.encoded),
                    ),
                    false,
                )

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toImplicitlyTaggedObject())
                }

            assertEquals("Session key id should be an OCTET STRING", exception.message)
        }

        @Test
        fun `Key id should be implicitly tagged`() {
            val encoding =
                ASN1Utils.makeSequence(
                    listOf(
                        DEROctetString(keyId),
                        SubjectPublicKeyInfo.getInstance(publicKey.encoded),
                    ),
                )

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toImplicitlyTaggedObject())
                }

            assertEquals("Session key id should be implicitly tagged", exception.message)
        }

        @Test
        fun `Public key should be a SUBJECT PUBLIC KEY INFO`() {
            val encoding =
                ASN1Utils.makeSequence(
                    listOf(
                        DEROctetString(keyId),
                        DERNull.INSTANCE,
                    ),
                    false,
                )

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toImplicitlyTaggedObject())
                }

            assertEquals(
                "Public key should be a SubjectPublicKeyInfo",
                exception.message,
            )
        }

        @Test
        fun `Public key should be implicitly tagged`() {
            val encoding =
                ASN1Utils.makeSequence(
                    listOf(
                        DEROctetString(keyId).toImplicitlyTaggedObject(),
                        SubjectPublicKeyInfo.getInstance(publicKey.encoded),
                    ),
                )

            val exception =
                assertThrows<SessionKeyException> {
                    SessionKey.decode(encoding.toImplicitlyTaggedObject())
                }

            assertEquals("Public key should be implicitly tagged", exception.message)
        }

        @Test
        fun `Valid session key should be output`() {
            val encoding = sessionKey.encode()

            val decodedSessionKey = SessionKey.decode(encoding.toImplicitlyTaggedObject())

            assertEquals(sessionKey, decodedSessionKey)
        }
    }
}
