package tech.relaycorp.relaynet.messages

import kotlin.test.assertEquals
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CertificateRotationTest {
    private val subjectCertificate = PDACertPath.PRIVATE_GW
    private val issuerCertificate = PDACertPath.PUBLIC_GW

    private val formatSignature = byteArrayOf(*"Relaynet".toByteArray(), 0x10, 0)

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should start with format signature`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            assertEquals(
                formatSignature.asList(),
                serialization.slice(0..9)
            )
        }

        @Test
        fun `Serialization should contain a 2-item sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            assertEquals(2, sequenceItems.size)
        }

        @Test
        fun `Subject certificate should be in sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            val certificateSerialized = ASN1Utils.getOctetString(sequenceItems.first()).octets
            assertEquals(subjectCertificate, Certificate.deserialize(certificateSerialized))
        }

        @Test
        fun `Chain certificates should be in sequence`() {
            val rotation = CertificateRotation(subjectCertificate, listOf(issuerCertificate))

            val serialization = rotation.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            val chainSequence = ASN1Sequence.getInstance(sequenceItems[1], false)
            assertEquals(1, chainSequence.size())
            val issuerSerialized =
                ASN1Utils.getOctetString(chainSequence.first() as ASN1TaggedObject).octets
            assertEquals(issuerCertificate, Certificate.deserialize(issuerSerialized))
        }
    }
}
