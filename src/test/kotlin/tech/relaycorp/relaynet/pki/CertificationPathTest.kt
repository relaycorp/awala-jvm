package tech.relaycorp.relaynet.pki

import kotlin.test.assertEquals
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

class CertificationPathTest {
    @Nested
    inner class Serialize {
        @Test
        fun `Leaf certificate should be serialized`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))

            val serialization = path.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val leafCertificateSerialized = ASN1Utils.getOctetString(sequence.first()).octets
            val leafCertificate = Certificate.deserialize(leafCertificateSerialized)
            assertEquals(PDACertPath.PDA, leafCertificate)
        }

        @Test
        fun `Chain should be serialized`() {
            val path = CertificationPath(PDACertPath.PDA, listOf(PDACertPath.PRIVATE_ENDPOINT))

            val serialization = path.serialize()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val chainSequence = ASN1Sequence.getInstance(sequence[1], false)
            assertEquals(1, chainSequence.size())
            val caSerialized =
                ASN1Utils.getOctetString(chainSequence.first() as ASN1TaggedObject).octets
            val ca = Certificate.deserialize(caSerialized)
            assertEquals(PDACertPath.PRIVATE_ENDPOINT, ca)
        }
    }
}
