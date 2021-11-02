package tech.relaycorp.relaynet.messages.payloads

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.DEROctetString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.utils.CDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

class CargoCollectionRequestTest {
    @Test
    fun `CDA should be accessible from instance`() {
        val ccr = CargoCollectionRequest(CDACertPath.PUBLIC_GW)

        assertEquals(CDACertPath.PUBLIC_GW, ccr.cargoDeliveryAuthorization)
    }

    @Nested
    inner class Serialize {
        @Test
        fun `Cargo Delivery Authorization should be included DER-encoded`() {
            val ccr = CargoCollectionRequest(CDACertPath.PUBLIC_GW)

            val serialization = ccr.serializePlaintext()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val cdaASN1 = ASN1Utils.getOctetString(sequence.first())
            assertEquals(CDACertPath.PUBLIC_GW, Certificate.deserialize(cdaASN1.octets))
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Malformed sequence should be refused`() {
            val serialization = "invalid".toByteArray()

            val exception =
                assertThrows<RAMFException> { CargoCollectionRequest.deserialize(serialization) }

            assertEquals("CCR is not a valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `Sequence should have at least one item`() {
            val serialization = ASN1Utils.serializeSequence(emptyArray(), false)

            val exception =
                assertThrows<RAMFException> { CargoCollectionRequest.deserialize(serialization) }

            assertEquals("CCR should have at least one item", exception.message)
        }

        @Test
        fun `Malformed CDAs should be refused`() {
            val serialization =
                ASN1Utils.serializeSequence(arrayOf(DEROctetString("invalid".toByteArray())), false)

            val exception =
                assertThrows<RAMFException> { CargoCollectionRequest.deserialize(serialization) }

            assertEquals("CDA contained in CCR is invalid", exception.message)
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Valid values should be accepted`() {
            val ccr = CargoCollectionRequest(CDACertPath.PUBLIC_GW)
            val serialization = ccr.serializePlaintext()

            val ccrDeserialized = CargoCollectionRequest.deserialize(serialization)

            assertEquals(CDACertPath.PUBLIC_GW, ccrDeserialized.cargoDeliveryAuthorization)
        }
    }
}
