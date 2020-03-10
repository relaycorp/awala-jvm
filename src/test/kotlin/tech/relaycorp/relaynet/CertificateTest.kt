package tech.relaycorp.relaynet

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
    fun createKeyPair(): KeyPair {
        return Keys.generateRSAKeyPair(2048)
    }

    fun createTestX500Name(): X500Name {
        return Certificate.buildX500Name("The C Name")
    }

    fun validCertificateOptions(): FullCertificateIssuanceOptions {
        val keys = createKeyPair()
        val x500Name = createTestX500Name()
        return FullCertificateIssuanceOptions(
                x500Name,
                keys.private,
                keys.public,
                2,
                LocalDateTime.now(),
                LocalDateTime.now().plusMonths(1),
                false,
                null,
                2
        )
    }

    @Test fun testGenerateRSAKeyPair() {
        val keyPair = Keys.generateRSAKeyPair(2048)
        assertNotNull(keyPair, "generateRSAKeyPair with a valid modulus should return a key")
    }
    @Test fun testGenerateRSAKeyPairKeys() {
        val keyPair = Keys.generateRSAKeyPair(2048)
        val publicKey = keyPair.public
        val privateKey = keyPair.private
        assertNotNull(publicKey, "generateRSAKeyPair should return a public key")
        assertNotNull(privateKey, "generateRSAKeyPair should return a private key")
    }
    @Test fun testGenerateRSAKeyPairWithInvalidModulus() {
        val exception = assertThrows<KeyError> {
            Keys.generateRSAKeyPair(1024)
        }
        assertEquals(
                "The modulus should be at least 2048 (got 1024)",
                exception.message
        )
    }

    @Test fun testX500Name() {
        val x500Name = createTestX500Name()
        assertNotNull(x500Name)
    }

    @Test fun testFullCertificateIssuanceOptions() {
        val options = validCertificateOptions()
        assertNotNull(options, "Valid inputs should create a Full Certificate Issuance Options object")
    }

    @Test fun testFCIOSetterMethods() {
        val keyPair = createKeyPair()
        val options = validCertificateOptions()
        options.isCA = true
        options.issuerCertificate = null
        options.issuerPrivateKey = keyPair.private
        options.subjectPublicKey = keyPair.public
        options.pathLenConstraint = 3
        options.serialNumber = 2
        options.validityStartDate = LocalDateTime.now().plusMonths(1)
        options.validityEndDate = LocalDateTime.now().plusMonths(2)
        assertNotNull(options, "Valid inputs should create a Full Certificate Issuance Options object")
    }
    @Test fun testShouldCreateValidX500Name() {
        val x500Name = createTestX500Name()
        val cName = x500Name.rdNs[0]
        assertNotNull(cName.equals("The C Name"))
    }

    @Test fun testShouldNotCreateInvalidX500Name() {
        val exception = assertThrows<CertificateError> {
            Certificate.buildX500Name("")
        }
        assertEquals(
                "Invalid CName in X500 Name",
                exception.message
        )
    }

    @Test fun testShouldCreateCertificate() {
        val options = validCertificateOptions()
        val newCertificate = Certificate.issue(options)
        // Check version number, should be v3
        assertEquals(newCertificate.certificateHolder.versionNumber, 3, "Should issue a certificate from valid options")
    }
    @Test fun testShouldHaveAValidSerialNumber() {
        val options = validCertificateOptions()
        val newCertificate = Certificate.issue(options)
        // Check version number, should be v3
        assertTrue(newCertificate.certificateHolder.serialNumber > BigInteger.ZERO, "Should issue a certificate from valid options")
    }
    @Test fun testShouldHaveAValidDefaultStartDate() {
        val options = validCertificateOptions()
        val newCertificate = Certificate.issue(options)
        assertEquals(newCertificate.certificateHolder.notBefore, Date.valueOf(LocalDate.now()), "Should create a certificate valid from now by default")
    }
    @Test fun testShouldHaveAValidDefaultEndDate() {
        val options = validCertificateOptions()
        val newCertificate = Certificate.issue(options)
        assertTrue(newCertificate.certificateHolder.notAfter > Date.valueOf(LocalDate.now()), "Should create a certificate end date after now")
    }
    @Test fun testShouldRejectInvalidStartDate() {
        val options = validCertificateOptions()
        options.validityStartDate = options.validityEndDate
        val exception = assertThrows<CertificateError> {
            Certificate.issue(options)
        }
        assertEquals(
                "The end date must be later than the start date",
                exception.message
        )
    }
}
// test(‘should create an X.509 v3 certificate’,
// test(‘should import the public key into the certificate’
// test(‘should be signed with the specified private key’
// test(‘should store the specified serial number’,
// test(‘should generate a serial number if none was set’,
// test(‘should create a certificate valid from now by default’
// test(‘should honor a custom start validity date’
// test(‘should honor a custom end validity date’
// test(‘should not accept an end date before the start date’
// test(‘should store the specified Common Name (CN) in the subject’
// test(‘should set issuer DN to that of subject when self-issuing certificates’
// test(‘should accept an issuer marked as CA’,
// test(‘should refuse an issuer certificate without extensions’,
// test(‘should refuse an issuer certificate with an empty set of extensions’,
// test(‘should refuse an issuer certificate without basic constraints extension’
// test(‘should refuse an issuer not marked as CA’,
// test(‘should set issuer DN to that of CA’,
