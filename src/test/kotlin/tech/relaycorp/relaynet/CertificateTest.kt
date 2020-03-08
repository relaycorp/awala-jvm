package tech.relaycorp.relaynet

import java.security.KeyPair
import java.time.LocalDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
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
        val keyPair = Keys.generateRSAKeyPair(-1)
        assertNotNull(keyPair, "generateRSAKeyPair with an invalid modulus should still return a key")
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
        assertNotNull(newCertificate, "Should issue a certificate from valid options")
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
