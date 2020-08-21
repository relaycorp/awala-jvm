package tech.relaycorp.relaynet.bindings.pdc

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.FullCertPath
import tech.relaycorp.relaynet.KeyPairSet
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.wrappers.x509.CertificateException
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ParcelCollectorTest {
    private val dummyParcelSerialized = "parcel".toByteArray()
    private val dummyACK: suspend () -> Unit = {}

    @Test
    fun `Parcel serialized should be honored`() {
        val collector = ParcelCollector(dummyParcelSerialized, emptySet(), dummyACK)

        assertEquals(dummyParcelSerialized.asList(), collector.parcelSerialized.asList())
    }

    @Test
    fun `Trusted certificates should be honored`() {
        val trustedCertificates = setOf(FullCertPath.PRIVATE_ENDPOINT)
        val collector = ParcelCollector(dummyParcelSerialized, trustedCertificates, dummyACK)

        assertEquals(trustedCertificates, collector.trustedCertificates)
    }

    @Test
    fun `ACK callback should be honored`() {
        val collector = ParcelCollector("parcel".toByteArray(), emptySet(), dummyACK)

        assertEquals(dummyACK, collector.ack)
    }

    @Nested
    inner class DeserializeAndValidateParcel {
        val recipientCertificate = FullCertPath.PRIVATE_ENDPOINT
        val senderCertificate = FullCertPath.PDA
        val payload = "payload".toByteArray()

        @Test
        fun `Malformed parcels should be refused`() {
            val collector =
                ParcelCollector("invalid".toByteArray(), setOf(recipientCertificate), dummyACK)

            assertThrows<RAMFException> { collector.deserializeAndValidateParcel() }
        }

        @Test
        fun `Parcels bound for public endpoints should be refused`() {
            val invalidParcel = Parcel("https://public.endpoint", payload, senderCertificate)
            val collector = ParcelCollector(
                invalidParcel.serialize(KeyPairSet.PDA_GRANTEE.private),
                setOf(recipientCertificate),
                dummyACK
            )

            val exception =
                assertThrows<InvalidMessageException> { collector.deserializeAndValidateParcel() }
            assertNull(exception.cause)
        }

        @Test
        fun `Unauthorized parcels should be refused`() {
            val invalidParcel = Parcel(
                recipientCertificate.subjectPrivateAddress,
                payload,
                FullCertPath.PUBLIC_GW // Unauthorized sender
            )
            val collector = ParcelCollector(
                invalidParcel.serialize(KeyPairSet.PUBLIC_GW.private),
                setOf(recipientCertificate),
                dummyACK
            )

            val exception =
                assertThrows<InvalidMessageException> { collector.deserializeAndValidateParcel() }
            assertTrue(exception.cause is CertificateException)
        }

        @Test
        fun `Valid parcels should be returned`() {
            val parcel = Parcel(
                recipientCertificate.subjectPrivateAddress,
                payload,
                senderCertificate
            )
            val collector = ParcelCollector(
                parcel.serialize(KeyPairSet.PDA_GRANTEE.private),
                setOf(recipientCertificate),
                dummyACK
            )

            val parcelDeserialized = collector.deserializeAndValidateParcel()

            assertEquals(parcel.recipientAddress, parcelDeserialized.recipientAddress)
            assertEquals(parcel.payload.asList(), parcelDeserialized.payload.asList())
            assertEquals(parcel.senderCertificate, parcelDeserialized.senderCertificate)
        }
    }
}
