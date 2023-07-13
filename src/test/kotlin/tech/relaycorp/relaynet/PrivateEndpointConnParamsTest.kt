package tech.relaycorp.relaynet

import java.security.PublicKey
import java.util.Base64
import kotlin.test.assertEquals
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class PrivateEndpointConnParamsTest {
    val internetAddress = "foo.relaycorp.tech"
    val identityKey: PublicKey = KeyPairSet.INTERNET_GW.public
    val deliveryAuth = CertificationPath(
        PDACertPath.PDA,
        listOf(PDACertPath.PRIVATE_ENDPOINT)
    )
    val sessionKey = SessionKeyPair.generate().sessionKey

    @Nested
    inner class Serialize {
        val params = PrivateEndpointConnParams(
            identityKey,
            internetAddress,
            deliveryAuth,
            sessionKey
        )

        @Test
        fun `Identity key should be serialized`() {
            val serialisation = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialisation)
            val identityKeyDecoded = SubjectPublicKeyInfo.getInstance(sequenceASN1[0], false)
            assertEquals(SubjectPublicKeyInfo.getInstance(identityKey.encoded), identityKeyDecoded)
        }

        @Test
        fun `Internet gateway address should be serialized`() {
            val serialisation = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeHeterogeneousSequence(serialisation)
            val internetGatewayAddress = ASN1Utils.getVisibleString(sequenceASN1[1]).string
            assertEquals(internetAddress, internetGatewayAddress)
        }

        @Test
        fun `Delivery auth should be serialized`() {
            val serialisation = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeSequence(serialisation)
            val deliveryAuthDecoded =
                CertificationPath.decode(sequenceASN1.getObjectAt(2) as ASN1TaggedObject)
            assertEquals(deliveryAuth.leafCertificate, deliveryAuthDecoded.leafCertificate)
            assertEquals(
                deliveryAuth.certificateAuthorities,
                deliveryAuthDecoded.certificateAuthorities
            )
        }

        @Test
        fun `Session key should be serialized`() {
            val serialisation = params.serialize()

            val sequenceASN1 = ASN1Utils.deserializeSequence(serialisation)
            val sessionKeyObject = sequenceASN1.getObjectAt(3) as ASN1TaggedObject
            val sessionKeyDecoded = SessionKey.decode(sessionKeyObject)
            assertEquals(sessionKey, sessionKeyDecoded)
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be DER sequence`() {
            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize("foo".toByteArray())
            }

            assertEquals("Serialization is not a DER sequence", exception.message)
        }

        @Test
        fun `Sequence should have at least 4 items`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    SubjectPublicKeyInfo.getInstance(identityKey.encoded),
                    DERVisibleString(internetAddress),
                    deliveryAuth.encode(),
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize(serialization)
            }

            assertEquals("Connection params should have at least 4 items", exception.message)
        }

        @Test
        fun `Identity key should be a valid public key`() {
            val serialization = ASN1Utils.serializeSequence(
                listOf(
                    DERNull.INSTANCE, // Invalid
                    DERVisibleString(internetAddress),
                    deliveryAuth.encode(),
                    sessionKey.encode(),
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize(serialization)
            }

            assertEquals("Invalid identity key", exception.message)
            assert(exception.cause is IllegalStateException)
        }

        @Test
        fun `Internet address should be syntactically valid`() {
            val malformedInternetAddress = "not really a domain name"
            val invalidParams = PrivateEndpointConnParams(
                identityKey,
                malformedInternetAddress,
                deliveryAuth,
                sessionKey
            )
            val serialization = invalidParams.serialize()

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize(serialization)
            }

            assertEquals(
                "Internet address is syntactically invalid ($malformedInternetAddress)",
                exception.message
            )
        }

        @Test
        fun `Delivery auth should be valid`() {
            val encoding = ASN1Utils.serializeSequence(
                listOf(
                    SubjectPublicKeyInfo.getInstance(identityKey.encoded),
                    DERVisibleString(internetAddress),
                    DERNull.INSTANCE, // Invalid
                    sessionKey.encode(),
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize(encoding)
            }

            assertEquals("Invalid delivery auth", exception.message)
            assert(exception.cause is CertificationPathException)
        }

        @Test
        fun `Session key should be valid`() {
            val encoding = ASN1Utils.serializeSequence(
                listOf(
                    SubjectPublicKeyInfo.getInstance(identityKey.encoded),
                    DERVisibleString(internetAddress),
                    deliveryAuth.encode(),
                    DERNull.INSTANCE, // Invalid
                ),
                false
            )

            val exception = assertThrows<InvalidNodeConnectionParams> {
                PrivateEndpointConnParams.deserialize(encoding)
            }

            assertEquals("Invalid session key", exception.message)
            assert(exception.cause is SessionKeyException)
        }

        @Test
        fun `Params should be output if serialization is valid`() {
            val params = PrivateEndpointConnParams(
                identityKey,
                internetAddress,
                deliveryAuth,
                sessionKey
            )
            val serialization = params.serialize()

            val deserializedParams = PrivateEndpointConnParams.deserialize(serialization)

            assertEquals(params.identityKey, deserializedParams.identityKey)
            assertEquals(params.internetGatewayAddress, deserializedParams.internetGatewayAddress)
            assertEquals(params.deliveryAuth.encode(), deserializedParams.deliveryAuth.encode())
            assertEquals(params.sessionKey, deserializedParams.sessionKey)
        }
    }
}
