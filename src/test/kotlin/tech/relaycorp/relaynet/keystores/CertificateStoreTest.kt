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

            store.save(CertificateStore.Scope.PDA, certificate)

            assertTrue(
                store.data.containsKey(CertificateStore.Scope.PDA to certificate.subjectPrivateAddress)
            )
            val certificationPaths =
                store.data[CertificateStore.Scope.PDA to certificate.subjectPrivateAddress]!!
            assertEquals(1, certificationPaths.size)
        }

        @Test
        fun `Certification path should be stored`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)

            assertTrue(
                store.data.containsKey(CertificateStore.Scope.PDA to certificate.subjectPrivateAddress)
            )
            val certificationPaths =
                store.data[CertificateStore.Scope.PDA to certificate.subjectPrivateAddress]!!
            assertEquals(1, certificationPaths.size)
        }
    }

    @Nested
    inner class RetrieveLatest {
        @Test
        fun `Existing certification path should be returned`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)

            val certificationPath =
                store.retrieveLatest(
                    CertificateStore.Scope.PDA,
                    certificate.subjectPrivateAddress
                )!!

            assertEquals(certificate, certificationPath.leafCertificate)
            assertEquals(certificateChain, certificationPath.chain)
        }

        @Test
        fun `Existing certification path of another scope should not be returned`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)

            assertNull(
                store.retrieveLatest(
                    CertificateStore.Scope.CDA,
                    certificate.subjectPrivateAddress
                )
            )
        }

        @Test
        fun `Null should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            assertNull(store.retrieveLatest(CertificateStore.Scope.PDA, "non-existent"))
        }

        @Test
        fun `Last to expire certificate should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)
            store.save(CertificateStore.Scope.PDA, aboutToExpireCertificate, certificateChain)

            val certificationPath =
                store.retrieveLatest(
                    CertificateStore.Scope.PDA,
                    certificate.subjectPrivateAddress
                )!!

            assertEquals(certificate, certificationPath.leafCertificate)
        }
    }

    @Nested
    inner class RetrieveAll {
        @Test
        fun `No certification path should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            val results = store.retrieveAll(CertificateStore.Scope.PDA, "non-existent")
            assertEquals(0, results.size)
        }

        @Test
        fun `All stored non-expired certification paths should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)
            store.save(CertificateStore.Scope.PDA, aboutToExpireCertificate, certificateChain)
            store.save(CertificateStore.Scope.PDA, expiredCertificate, certificateChain)

            val allCertificationPaths =
                store.retrieveAll(CertificateStore.Scope.PDA, certificate.subjectPrivateAddress)

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
                store.data[CertificateStore.Scope.PDA to certificate.subjectPrivateAddress] =
                    listOf(
                        Pair(ZonedDateTime.now().plusDays(1), "malformed".toByteArray())
                    )

                val exception = assertThrows<KeyStoreBackendException> {
                    store.retrieveAll(CertificateStore.Scope.PDA, certificate.subjectPrivateAddress)
                }
                assertEquals("Malformed certification path", exception.message)
            }

        @Test
        fun `Empty certification path should throw KeyStoreBackendException`() = runBlockingTest {
            val store = MockCertificateStore()
            store.data[CertificateStore.Scope.PDA to certificate.subjectPrivateAddress] = listOf(
                Pair(
                    ZonedDateTime.now().plusDays(1),
                    ASN1Utils.serializeSequence(emptyList())
                )
            )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveAll(CertificateStore.Scope.PDA, certificate.subjectPrivateAddress)
            }
            assertEquals("Empty certification path", exception.message)
        }
    }

    @Nested
    inner class DeleteExpired {
        @Test
        fun `All expired certification paths are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(CertificateStore.Scope.PDA, expiredCertificate, certificateChain)

            store.deleteExpired()

            assertTrue(store.data.isEmpty())
        }
    }

    @Nested
    inner class Delete {
        @Test
        fun `All certification paths of a certain address are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(CertificateStore.Scope.PDA, certificate, certificateChain)
            store.save(CertificateStore.Scope.PDA, aboutToExpireCertificate, certificateChain)
            store.save(CertificateStore.Scope.PDA, unrelatedCertificate, certificateChain)

            store.delete(CertificateStore.Scope.PDA, certificate.subjectPrivateAddress)

            assertNull(store.data[CertificateStore.Scope.PDA to certificate.subjectPrivateAddress])
            assertTrue(
                store.data[CertificateStore.Scope.PDA to unrelatedCertificate.subjectPrivateAddress]!!
                    .isNotEmpty()
            )
        }
    }
}
