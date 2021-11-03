package tech.relaycorp.relaynet

import java.security.PublicKey
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class PublicNodeConnectionParamsTest {
    val publicAddress = "foo.relaycorp.tech"

    val identityKey: PublicKey = KeyPairSet.PUBLIC_GW.public
    val sessionKey = SessionKeyPair.generate().sessionKey

    @Nested
    inner class Serialize {
        @Test
        fun `Public address should be serialized`() {
            val params = PublicNodeConnectionParams(publicAddress, identityKey, sessionKey)

            val serialization = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            assertEquals(publicAddress, ASN1Utils.getVisibleString(sequenceASN1[0]).string)
        }

        @Test
        fun `Identity key should be serialized`() {
            val params = PublicNodeConnectionParams(publicAddress, identityKey, sessionKey)

            val serialization = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val identityKeySerialized = ASN1Utils.getOctetString(sequenceASN1[1]).octets
            assertEquals(identityKey.encoded.asList(), identityKeySerialized.asList())
        }

        @Test
        fun `Session key id should be serialized`() {
            val params = PublicNodeConnectionParams(publicAddress, identityKey, sessionKey)

            val serialization = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val sessionKeyASN1 = ASN1Sequence.getInstance(sequenceASN1[2], false)
            val keyIdASN1 =
                ASN1Utils.getOctetString(sessionKeyASN1.getObjectAt(0) as ASN1TaggedObject)
            assertEquals(sessionKey.keyId.asList(), keyIdASN1.octets.asList())
        }

        @Test
        fun `Session public key should be serialized`() {
            val params = PublicNodeConnectionParams(publicAddress, identityKey, sessionKey)

            val serialization = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val sessionKeyASN1 = ASN1Sequence.getInstance(sequenceASN1[2], false)
            val sessionPublicKeyASN1 =
                ASN1Utils.getOctetString(sessionKeyASN1.getObjectAt(1) as ASN1TaggedObject)
            assertEquals(
                sessionKey.publicKey.encoded.asList(),
                sessionPublicKeyASN1.octets.asList()
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be DER sequence`() {
            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(byteArrayOf(0))
            }

            assertEquals("Serialization is not a DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least three items`() {
            val invalidSequence = ASN1Utils.serializeSequence(
                listOf(
                    DERVisibleString("one"),
                    DERVisibleString("two"),
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(invalidSequence)
            }

            assertEquals(
                "Connection params sequence should have at least 3 items (got 2)",
                exception.message
            )
        }

        @Test
        fun `Public address should be syntactically valid`() {
            val malformedPublicAddress = "not really a domain name"
            val invalidParams = PublicNodeConnectionParams(
                malformedPublicAddress,
                identityKey,
                sessionKey
            )
            val invalidSerialization = invalidParams.serialize()

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(invalidSerialization)
            }

            assertEquals(
                "Public address is syntactically invalid ($malformedPublicAddress)",
                exception.message
            )
        }

        @Test
        fun `Identity key should be a valid RSA public key`() {
            val invalidParams = PublicNodeConnectionParams(
                publicAddress,
                sessionKey.publicKey, // Invalid
                sessionKey
            )
            val invalidSerialization = invalidParams.serialize()

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(invalidSerialization)
            }

            assertEquals(
                "Identity key is not a valid RSA public key",
                exception.message
            )
            assertTrue(exception.cause is KeyException)
        }

        @Test
        fun `Session key SEQUENCE should contain at least two items`() {
            val invalidSequence = ASN1Utils.serializeSequence(
                listOf(
                    DERVisibleString(publicAddress),
                    DEROctetString(identityKey.encoded),
                    ASN1Utils.makeSequence(listOf(DERVisibleString("foo")), false)
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(invalidSequence)
            }

            assertEquals(
                "Session key sequence should have at least 2 items (got 1)",
                exception.message
            )
        }

        @Test
        fun `Session key should be a valid ECDH public key`() {
            val invalidParams = PublicNodeConnectionParams(
                publicAddress,
                identityKey,
                SessionKey(sessionKey.keyId, identityKey) // Invalid
            )
            val invalidSerialization = invalidParams.serialize()

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PublicNodeConnectionParams.deserialize(invalidSerialization)
            }

            assertEquals(
                "Session key is not a valid EC public key",
                exception.message
            )
            assertTrue(exception.cause is KeyException)
        }

        @Test
        fun `Valid serialization should be deserialized`() {
            val params = PublicNodeConnectionParams(publicAddress, identityKey, sessionKey)
            val serialization = params.serialize()

            val paramsDeserialized = PublicNodeConnectionParams.deserialize(serialization)

            assertEquals(publicAddress, paramsDeserialized.publicAddress)
            assertEquals(
                identityKey.encoded.asList(),
                paramsDeserialized.identityKey.encoded.asList()
            )
            assertEquals(sessionKey, paramsDeserialized.sessionKey)
        }
    }
}
