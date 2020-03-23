package tech.relaycorp.relaynet.wrappers.x509

import java.math.BigInteger
import java.security.KeyPair
import java.sql.Date
import java.time.LocalDate
import java.time.LocalDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.x500.X500Name
import org.junit.jupiter.api.assertThrows

class CertificateTest {
    private fun createKeyPair(): KeyPair {
        return Keys.generateRSAKeyPair(2048)
    }

    private fun createTestX500Name(): X500Name {
        return Certificate.buildX500Name("The C Name")
    }

    @Test
    fun testGenerateRSAKeyPair() {
        val keyPair = Keys.generateRSAKeyPair(2048)
        assertNotNull(keyPair, "generateRSAKeyPair with a valid modulus should return a key")
    }

    @Test
    fun testGenerateRSAKeyPairKeys() {
        val keyPair = Keys.generateRSAKeyPair(2048)
        val publicKey = keyPair.public
        val privateKey = keyPair.private
        assertNotNull(publicKey, "generateRSAKeyPair should return a public key")
        assertNotNull(privateKey, "generateRSAKeyPair should return a private key")
    }

    @Test
    fun testGenerateRSAKeyPairWithInvalidModulus() {
        val exception = assertThrows<KeyError> {
            Keys.generateRSAKeyPair(1024)
        }
        assertEquals(
            "The modulus should be at least 2048 (got 1024)",
            exception.message
        )
    }

    @Test
    fun generateSecureRandomNumber() {
        val randomNumber = CryptoUtil.generateRandom64BitValue()
        assertNotNull(randomNumber, "Should generate a 64bit Random Number")
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
        val exception = assertThrows<CertificateError> {
            Certificate.buildX500Name("")
        }
        assertEquals(
            "Invalid CName in X500 Name",
            exception.message
        )
    }
//    @Test fun testGetPathLengthDefault() {
//        assertEquals(Certificate.MAX_PATH_LENGTH_CONSTRAINT, 2)
//    }

    @Test
    fun testShouldCreateCertificate() {
        val commonName = createTestX500Name()
        val keyPair = createKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        val validityEndDate = LocalDateTime.now().plusMonths(2)
        val pathLenConstraint = 2
        val newCertificate = Certificate.issue(
            commonName,
            issuerPrivateKey,
            subjectPublicKey,
            serialNumber,
            validityStartDate,
            validityEndDate
        )
        // Check version number, should be v3
        assertEquals(newCertificate.certificateHolder.versionNumber, 3, "Should issue a certificate from valid options")
    }

    @Test
    fun testShouldHaveAValidSerialNumber() {
        val commonName = createTestX500Name()
        val keyPair = createKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        val validityEndDate = LocalDateTime.now().plusMonths(2)
        val pathLenConstraint = 2
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
    fun testShouldHaveAValidDefaultStartDate() {

        val commonName = createTestX500Name()
        val keyPair = createKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val pathLenConstraint = 2
        val newCertificate = Certificate.issue(
            commonName,
            issuerPrivateKey,
            subjectPublicKey,
            serialNumber
        )

        assertEquals(
            newCertificate.certificateHolder.notBefore,
            Date.valueOf(LocalDate.now()),
            "Should create a certificate valid from now by default"
        )
    }

    @Test
    fun testShouldHaveAValidDefaultEndDate() {
        val commonName = createTestX500Name()
        val keyPair = createKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val pathLenConstraint = 2
        val newCertificate = Certificate.issue(
            commonName,
            issuerPrivateKey,
            subjectPublicKey,
            serialNumber
        )

        assertTrue(
            newCertificate.certificateHolder.notAfter > Date.valueOf(LocalDate.now()),
            "Should create a certificate end date after now"
        )
    }

    @Test
    fun testShouldRejectInvalidStartDate() {
        val commonName = createTestX500Name()
        val keyPair = createKeyPair()
        val issuerPrivateKey = keyPair.private
        val subjectPublicKey = keyPair.public
        val serialNumber: Long = 2
        val validityStartDate = LocalDateTime.now().plusMonths(1)
        // Set start and dates the same
        val validityEndDate = validityStartDate
        val exception = assertThrows<CertificateError> {
            Certificate.issue(
                commonName,
                issuerPrivateKey,
                subjectPublicKey,
                serialNumber,
                validityStartDate,
                validityEndDate
            )
        }
        assertEquals(
            "The end date must be later than the start date",
            exception.message
        )
    }
}
