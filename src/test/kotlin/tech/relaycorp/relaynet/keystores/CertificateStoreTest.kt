package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.MockCertificateStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@ExperimentalCoroutinesApi
class CertificateStoreTest {

    private val certificate = PDACertPath.PRIVATE_GW
    private val certificateChain = listOf(PDACertPath.PUBLIC_GW, PDACertPath.PUBLIC_GW)

    private val aboutToExpireCertificate = Certificate.issue(
        "foo",
        certificate.subjectPublicKey,
        KeyPairSet.PRIVATE_GW.private,
        ZonedDateTime.now().plusMinutes(1),
        validityStartDate = ZonedDateTime.now().minusSeconds(2)
    )

    private val expiredCertificate = Certificate.issue(
        "foo",
        certificate.subjectPublicKey,
        KeyPairSet.PRIVATE_GW.private,
        ZonedDateTime.now().minusSeconds(1),
        validityStartDate = ZonedDateTime.now().minusSeconds(2)
    )

    private val unrelatedCertificate = PDACertPath.PRIVATE_ENDPOINT

    @Nested
    inner class Save {
        @Test
        fun `Certificate should be stored`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate)

            assertTrue(store.data.containsKey(certificate.subjectPrivateAddress))
            val certificationPaths = store.data[certificate.subjectPrivateAddress]!!
            assertEquals(1, certificationPaths.size)
        }

        @Test
        fun `Certification path should be stored`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain)

            assertTrue(store.data.containsKey(certificate.subjectPrivateAddress))
            val certificationPaths = store.data[certificate.subjectPrivateAddress]!!
            assertEquals(1, certificationPaths.size)
        }
    }

    @Nested
    inner class RetrieveLatest {
        @Test
        fun `Existing certification path should be returned`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(certificate, certificateChain)

            val certificationPath = store.retrieveLatest(certificate.subjectPrivateAddress)!!

            assertEquals(certificate, certificationPath.leafCertificate)
            assertEquals(certificateChain, certificationPath.chain)
        }

        @Test
        fun `Null should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            assertNull(store.retrieveLatest("non-existent"))
        }

        @Test
        fun `Last to expire certificate should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain)
            store.save(aboutToExpireCertificate, certificateChain)

            val certificationPath = store.retrieveLatest(certificate.subjectPrivateAddress)!!

            assertEquals(certificate, certificationPath.leafCertificate)
        }
    }

    @Nested
    inner class RetrieveAll {
        @Test
        fun `No certification path should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            assertEquals(0, store.retrieveAll("non-existent").size)
        }

        @Test
        fun `All stored non-expired certification paths should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain)
            store.save(aboutToExpireCertificate, certificateChain)
            store.save(expiredCertificate, certificateChain)

            val allCertificationPaths = store.retrieveAll(certificate.subjectPrivateAddress)

            assertEquals(2, allCertificationPaths.size)
            assertContains(
                allCertificationPaths.map { it.leafCertificate },
                certificate
            )
            assertContains(
                allCertificationPaths.map { it.leafCertificate },
                aboutToExpireCertificate
            )
        }

        @Test
        fun `Malformed certification path should throw KeyStoreBackendException`() =
            runBlockingTest {
                val store = MockCertificateStore()
                store.data[certificate.subjectPrivateAddress] = listOf(
                    Pair(ZonedDateTime.now().plusDays(1), "malformed".toByteArray())
                )

                val exception = assertThrows<KeyStoreBackendException> {
                    store.retrieveAll(certificate.subjectPrivateAddress)
                }
                assertEquals("Malformed certification path", exception.message)
            }

        @Test
        fun `Empty certification path should throw KeyStoreBackendException`() = runBlockingTest {
            val store = MockCertificateStore()
            store.data[certificate.subjectPrivateAddress] = listOf(
                Pair(
                    ZonedDateTime.now().plusDays(1),
                    ASN1Utils.serializeSequence(emptyList())
                )
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveAll(certificate.subjectPrivateAddress)
            }
            assertEquals("Empty certification path", exception.message)
        }
    }

    @Nested
    inner class DeleteExpired {
        @Test
        fun `All expired certification paths are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(expiredCertificate, certificateChain)

            store.deleteExpired()

            assertTrue(store.data.isEmpty())
        }
    }

    @Nested
    inner class Delete {
        @Test
        fun `All certification paths of a certain address are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(certificate, certificateChain)
            store.save(aboutToExpireCertificate, certificateChain)
            store.save(unrelatedCertificate, certificateChain)

            store.delete(certificate.subjectPrivateAddress)

            assertNull(store.data[certificate.subjectPrivateAddress])
            assertTrue(store.data[unrelatedCertificate.subjectPrivateAddress]!!.isNotEmpty())
        }
    }
}
