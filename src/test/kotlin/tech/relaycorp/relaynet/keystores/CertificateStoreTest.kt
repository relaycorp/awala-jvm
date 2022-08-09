package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.MockCertificateStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@ExperimentalCoroutinesApi
class CertificateStoreTest {

    private val certificate = PDACertPath.PRIVATE_GW
    private val certificateChain = listOf(PDACertPath.INTERNET_GW, PDACertPath.INTERNET_GW)
    private val issuerAddress = PDACertPath.INTERNET_GW.subjectId

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
        fun `Certificate should be stored`() = runTest {
            val store = MockCertificateStore()

            store.save(CertificationPath(certificate, emptyList()), issuerAddress)

            assertTrue(
                store.data.containsKey(certificate.subjectId to issuerAddress)
            )
            val certificationPaths =
                store.data[certificate.subjectId to issuerAddress]!!
            assertEquals(1, certificationPaths.size)
        }

        @Test
        fun `Certification path should be stored`() = runTest {
            val store = MockCertificateStore()

            store.save(CertificationPath(certificate, certificateChain), issuerAddress)

            assertTrue(
                store.data.containsKey(certificate.subjectId to issuerAddress)
            )
            val certificationPaths =
                store.data[certificate.subjectId to issuerAddress]!!
            assertEquals(1, certificationPaths.size)
            assertEquals(
                CertificationPath(certificate, certificateChain).serialize().asList(),
                certificationPaths.first().second.asList()
            )
        }
    }

    @Nested
    inner class RetrieveLatest {
        @Test
        fun `Existing certification path should be returned`() = runTest {
            val store = MockCertificateStore()
            store.save(CertificationPath(certificate, certificateChain), issuerAddress)

            val certificationPath = store.retrieveLatest(
                certificate.subjectId,
                issuerAddress
            )!!

            assertEquals(certificate, certificationPath.leafCertificate)
            assertEquals(certificateChain, certificationPath.certificateAuthorities)
        }

        @Test
        fun `Existing certification path of another issuer should not be returned`() =
            runTest {
                val store = MockCertificateStore()
                store.save(CertificationPath(certificate, certificateChain), issuerAddress)

                assertNull(
                    store.retrieveLatest(
                        certificate.subjectId,
                        "another-address"
                    )
                )
            }

        @Test
        fun `Null should be returned if there are none`() = runTest {
            val store = MockCertificateStore()

            assertNull(store.retrieveLatest("non-existent", issuerAddress))
        }

        @Test
        fun `Last to expire certificate should be returned`() = runTest {
            val store = MockCertificateStore()

            store.save(CertificationPath(certificate, certificateChain), issuerAddress)
            store.save(CertificationPath(aboutToExpireCertificate, certificateChain), issuerAddress)

            val certificationPath =
                store.retrieveLatest(
                    certificate.subjectId,
                    issuerAddress
                )!!

            assertEquals(certificate, certificationPath.leafCertificate)
        }
    }

    @Nested
    inner class RetrieveAll {
        @Test
        fun `No certification path should be returned if there are none`() = runTest {
            val store = MockCertificateStore()

            val results = store.retrieveAll("non-existent", issuerAddress)
            assertEquals(0, results.size)
        }

        @Test
        fun `All stored non-expired certification paths should be returned`() = runTest {
            val store = MockCertificateStore()
            store.save(CertificationPath(certificate, certificateChain), issuerAddress)
            store.save(CertificationPath(aboutToExpireCertificate, certificateChain), issuerAddress)
            store.forceSave(CertificationPath(expiredCertificate, certificateChain), issuerAddress)

            val allCertificationPaths =
                store.retrieveAll(certificate.subjectId, issuerAddress)

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
        fun `Stored non-expired certification paths from another issuer should not be returned`() =
            runTest {
                val store = MockCertificateStore()

                store.save(CertificationPath(certificate, certificateChain), issuerAddress)
                store.save(
                    CertificationPath(PDACertPath.PRIVATE_ENDPOINT, certificateChain),
                    "another-issuer"
                )

                val allCertificationPaths =
                    store.retrieveAll(certificate.subjectId, issuerAddress)

                assertEquals(1, allCertificationPaths.size)
                assertEquals(certificate, allCertificationPaths.first().leafCertificate)
            }

        @Test
        fun `Malformed certification path should throw error`() = runTest {
            val store = MockCertificateStore()
            store.data[certificate.subjectId to issuerAddress] =
                listOf(
                    Pair(ZonedDateTime.now().plusDays(1), "malformed".toByteArray())
                )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveAll(certificate.subjectId, issuerAddress)
            }

            assertEquals("Stored certification path is malformed", exception.message)
            assertTrue(exception.cause is CertificationPathException)
        }
    }

    @Nested
    inner class DeleteExpired {
        @Test
        fun `All expired certification paths are deleted`() = runTest {
            val store = MockCertificateStore()
            store.save(CertificationPath(expiredCertificate, certificateChain), issuerAddress)
            store.save(CertificationPath(expiredCertificate, certificateChain), "another-issuer")

            store.deleteExpired()

            assertTrue(store.data.isEmpty())
        }
    }

    @Nested
    inner class Delete {
        @Test
        fun `All certification paths of a certain address are deleted`() = runTest {
            val store = MockCertificateStore()
            store.save(CertificationPath(certificate, certificateChain), issuerAddress)
            store.save(CertificationPath(aboutToExpireCertificate, certificateChain), issuerAddress)
            store.save(CertificationPath(unrelatedCertificate, certificateChain), issuerAddress)

            store.delete(certificate.subjectId, issuerAddress)

            assertNull(store.data[certificate.subjectId to issuerAddress])
            assertTrue(
                store.data[unrelatedCertificate.subjectId to issuerAddress]!!
                    .isNotEmpty()
            )
        }

        @Test
        fun `Only certification paths of a certain address and issuer are deleted`() =
            runTest {
                val store = MockCertificateStore()
                store.save(CertificationPath(certificate, certificateChain), issuerAddress)
                store.save(CertificationPath(certificate, certificateChain), "another-issuer")

                store.delete(certificate.subjectId, issuerAddress)

                assertNull(store.data[certificate.subjectId to issuerAddress])
                assertTrue(
                    store.data[certificate.subjectId to "another-issuer"]!!.isNotEmpty()
                )
            }
    }
}
