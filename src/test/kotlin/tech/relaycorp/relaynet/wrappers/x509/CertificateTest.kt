package tech.relaycorp.relaynet.wrappers.x509

import java.math.BigInteger
import java.sql.Date
import java.time.LocalDate
import java.time.LocalDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.x500.X500Name
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair

class CertificateTest {
    private fun createTestX500Name(): X500Name {
        return Certificate.buildX500Name("The C Name")
    }

    @Test
    fun `Certificate version should be 3`() {
        val commonName = createTestX500Name()
        val keyPair = generateRSAKeyPair()
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        val validityEndDate = LocalDateTime.now().plusMonths(2)
        val newCertificate = Certificate.issue(
            commonName,
            keyPair.private,
            keyPair.public,
            serialNumber,
            validityStartDate,
            validityEndDate
        )

        assertEquals(3, newCertificate.certificateHolder.versionNumber)
    }

    @Test
    fun testShouldHaveAValidSerialNumber() {
        val commonName = createTestX500Name()
        val keyPair = generateRSAKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        val validityEndDate = LocalDateTime.now().plusMonths(2)
        val newCertificate = Certificate.issue(
            commonName,
            issuerPrivateKey,
            subjectPublicKey,
            serialNumber,
            validityStartDate,
            validityEndDate
        )

        // Check version number, should be v3
        assertTrue(
            newCertificate.certificateHolder.serialNumber > BigInteger.ZERO,
            "Should issue a certificate from valid options"
        )
    }

    @Test
    fun `Validity start date should be set to current time by default`() {
        val commonName = createTestX500Name()
        val keyPair = generateRSAKeyPair()
        val serialNumber: Long = 2
        val newCertificate = Certificate.issue(
            commonName,
            keyPair.private,
            keyPair.public,
            serialNumber
        )

        assertEquals(
            Date.valueOf(LocalDate.now()),
            newCertificate.certificateHolder.notBefore
        )
    }

    // TODO: There shouldn't be any default end date. It must be explicit.
    @Test
    fun testShouldHaveAValidDefaultEndDate() {
        val commonName = createTestX500Name()
        val keyPair = generateRSAKeyPair()
        val serialNumber: Long = 2
        val newCertificate = Certificate.issue(
            commonName,
            keyPair.private,
            keyPair.public,
            serialNumber
        )

        assertTrue(
            newCertificate.certificateHolder.notAfter > Date.valueOf(LocalDate.now()),
            "Should create a certificate end date after now"
        )
    }

    @Test
    fun `The end date should be later than the start date`() {
        val commonName = createTestX500Name()
        val keyPair = generateRSAKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        val exception = assertThrows<CertificateException> {
            Certificate.issue(
                commonName,
                issuerPrivateKey,
                subjectPublicKey,
                serialNumber,
                validityStartDate,
                validityStartDate // Same as start date
            )
        }
        assertEquals(
            "The end date must be later than the start date",
            exception.message
        )
    }

    @Test
    fun testX500Name() {
        val x500Name = createTestX500Name()
        assertNotNull(x500Name)
    }

    @Test
    fun testShouldCreateValidX500Name() {
        val x500Name = createTestX500Name()
        val cName = x500Name.rdNs[0]
        assertNotNull(cName.equals("The C Name"))
    }

    @Test
    fun testShouldNotCreateInvalidX500Name() {
        val exception = assertThrows<CertificateException> {
            Certificate.buildX500Name("")
        }
        assertEquals(
            "Invalid CName in X500 Name",
            exception.message
        )
    }
}
