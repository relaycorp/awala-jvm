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
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
import tech.relaycorp.relaynet.utils.KeyPairSet
import tech.relaycorp.relaynet.utils.MockCertificateStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@ExperimentalCoroutinesApi
class CertificateStoreTest {

    private val certificate = PDACertPath.PRIVATE_GW
    private val certificateChain = listOf(PDACertPath.PUBLIC_GW, PDACertPath.PUBLIC_GW)
    private val issuerAddress = PDACertPath.PUBLIC_GW.subjectPrivateAddress

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

            store.save(certificate, issuerPrivateAddress = issuerAddress)

            assertTrue(
                store.data.containsKey(certificate.subjectPrivateAddress to issuerAddress)
            )
            val certificationPaths =
                store.data[certificate.subjectPrivateAddress to issuerAddress]!!
            assertEquals(1, certificationPaths.size)
        }

        @Test
        fun `Certification path should be stored`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain, issuerAddress)

            assertTrue(
                store.data.containsKey(certificate.subjectPrivateAddress to issuerAddress)
            )
            val certificationPaths =
                store.data[certificate.subjectPrivateAddress to issuerAddress]!!
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
        fun `Existing certification path should be returned`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(certificate, certificateChain, issuerAddress)

            val certificationPath = store.retrieveLatest(
                certificate.subjectPrivateAddress,
                issuerAddress
            )!!

            assertEquals(certificate, certificationPath.leafCertificate)
            assertEquals(certificateChain, certificationPath.chain)
        }

        @Test
        fun `Existing certification path of another issuer should not be returned`() =
            runBlockingTest {
                val store = MockCertificateStore()
                store.save(certificate, certificateChain, issuerAddress)

                assertNull(
                    store.retrieveLatest(
                        certificate.subjectPrivateAddress,
                        "another-address"
                    )
                )
            }

        @Test
        fun `Null should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            assertNull(store.retrieveLatest("non-existent", issuerAddress))
        }

        @Test
        fun `Last to expire certificate should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain, issuerAddress)
            store.save(aboutToExpireCertificate, certificateChain, issuerAddress)

            val certificationPath =
                store.retrieveLatest(
                    certificate.subjectPrivateAddress,
                    issuerAddress
                )!!

            assertEquals(certificate, certificationPath.leafCertificate)
        }
    }

    @Nested
    inner class RetrieveAll {
        @Test
        fun `No certification path should be returned if there are none`() = runBlockingTest {
            val store = MockCertificateStore()

            val results = store.retrieveAll("non-existent", issuerAddress)
            assertEquals(0, results.size)
        }

        @Test
        fun `All stored non-expired certification paths should be returned`() = runBlockingTest {
            val store = MockCertificateStore()

            store.save(certificate, certificateChain, issuerAddress)
            store.save(aboutToExpireCertificate, certificateChain, issuerAddress)
            store.save(expiredCertificate, certificateChain, issuerAddress)

            val allCertificationPaths =
                store.retrieveAll(certificate.subjectPrivateAddress, issuerAddress)

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
            runBlockingTest {
                val store = MockCertificateStore()

                store.save(certificate, certificateChain, issuerAddress)
                store.save(PDACertPath.PRIVATE_ENDPOINT, certificateChain, "another-issuer")

                val allCertificationPaths =
                    store.retrieveAll(certificate.subjectPrivateAddress, issuerAddress)

                assertEquals(1, allCertificationPaths.size)
                assertEquals(certificate, allCertificationPaths.first().leafCertificate)
            }

        @Test
        fun `Malformed certification path should throw error`() = runBlockingTest {
            val store = MockCertificateStore()
            store.data[certificate.subjectPrivateAddress to issuerAddress] =
                listOf(
                    Pair(ZonedDateTime.now().plusDays(1), "malformed".toByteArray())
                )

            val exception = assertThrows<KeyStoreBackendException> {
                store.retrieveAll(certificate.subjectPrivateAddress, issuerAddress)
            }

            assertEquals("Stored certification path is malformed", exception.message)
            assertTrue(exception.cause is CertificationPathException)
        }
    }

    @Nested
    inner class DeleteExpired {
        @Test
        fun `All expired certification paths are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(expiredCertificate, certificateChain, issuerAddress)
            store.save(expiredCertificate, certificateChain, "another-issuer")

            store.deleteExpired()

            assertTrue(store.data.isEmpty())
        }
    }

    @Nested
    inner class Delete {
        @Test
        fun `All certification paths of a certain address are deleted`() = runBlockingTest {
            val store = MockCertificateStore()
            store.save(certificate, certificateChain, issuerAddress)
            store.save(aboutToExpireCertificate, certificateChain, issuerAddress)
            store.save(unrelatedCertificate, certificateChain, issuerAddress)

            store.delete(certificate.subjectPrivateAddress, issuerAddress)

            assertNull(store.data[certificate.subjectPrivateAddress to issuerAddress])
            assertTrue(
                store.data[unrelatedCertificate.subjectPrivateAddress to issuerAddress]!!
                    .isNotEmpty()
            )
        }

        @Test
        fun `Only certification paths of a certain address and issuer are deleted`() =
            runBlockingTest {
                val store = MockCertificateStore()
                store.save(certificate, certificateChain, issuerAddress)
                store.save(certificate, certificateChain, "another-issuer")

                store.delete(certificate.subjectPrivateAddress, issuerAddress)

                assertNull(store.data[certificate.subjectPrivateAddress to issuerAddress])
                assertTrue(
                    store.data[certificate.subjectPrivateAddress to "another-issuer"]!!.isNotEmpty()
                )
            }
    }
}
