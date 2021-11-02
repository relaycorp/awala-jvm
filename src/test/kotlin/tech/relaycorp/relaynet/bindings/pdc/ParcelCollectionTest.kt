package tech.relaycorp.relaynet.bindings.pdc

import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.messages.InvalidMessageException
import tech.relaycorp.relaynet.messages.Parcel
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

@ExperimentalCoroutinesApi
class ParcelCollectionTest {
    private val dummyParcelSerialized = "parcel".toByteArray()
    private val dummyACK: suspend () -> Unit = {}

    @Test
    fun `Parcel serialized should be honored`() {
        val collector = ParcelCollection(dummyParcelSerialized, emptySet(), dummyACK)

        assertEquals(dummyParcelSerialized.asList(), collector.parcelSerialized.asList())
    }

    @Test
    fun `Trusted certificates should be honored`() {
        val trustedCertificates = setOf(PDACertPath.PRIVATE_ENDPOINT)
        val collector = ParcelCollection(dummyParcelSerialized, trustedCertificates, dummyACK)

        assertEquals(trustedCertificates, collector.trustedCertificates)
    }

    @Test
    fun `ACK callback should be honored`() {
        val collector = ParcelCollection("parcel".toByteArray(), emptySet(), dummyACK)

        assertEquals(dummyACK, collector.ack)
    }

    @Nested
    inner class DeserializeAndValidateParcel {
        private val recipientCertificate = PDACertPath.PRIVATE_ENDPOINT
        private val senderCertificate = PDACertPath.PDA
        val payload = "payload".toByteArray()

        @Test
        fun `Malformed parcels should be refused`() {
            val collector =
                ParcelCollection("invalid".toByteArray(), setOf(recipientCertificate), dummyACK)

            assertThrows<RAMFException> { collector.deserializeAndValidateParcel() }
        }

        @Test
        fun `Parcels bound for public endpoints should be refused`() {
            val invalidParcel = Parcel("https://public.endpoint", payload, senderCertificate)
            val collector = ParcelCollection(
                invalidParcel.serialize(KeyPairSet.PDA_GRANTEE.private),
                setOf(recipientCertificate),
                dummyACK
            )

            val exception =
                assertThrows<InvalidMessageException> { collector.deserializeAndValidateParcel() }
            assertNull(exception.cause)
        }

        @Test
        fun `Parcels from unauthorized senders should be refused`() {
            val invalidParcel = Parcel(
                recipientCertificate.subjectPrivateAddress,
                payload,
                PDACertPath.PUBLIC_GW // Unauthorized sender
            )
            val collector = ParcelCollection(
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
            val collector = ParcelCollection(
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
