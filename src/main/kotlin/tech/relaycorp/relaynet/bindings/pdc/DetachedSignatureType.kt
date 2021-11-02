package tech.relaycorp.relaynet.bindings.pdc

import java.security.PrivateKey
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import tech.relaycorp.relaynet.OIDs
import tech.relaycorp.relaynet.crypto.SignedData
import tech.relaycorp.relaynet.crypto.SignedDataException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import tech.relaycorp.relaynet.wrappers.x509.CertificateException

/**
 * Utility to sign and verify CMS SignedData values where the plaintext is not encapsulated (to
 * avoid re-encoding the plaintext for performance reasons), and the signer's certificate is
 * encapsulated.
 */
enum class DetachedSignatureType(internal val oid: ASN1ObjectIdentifier) {
    PARCEL_DELIVERY(OIDs.DETACHED_SIGNATURE.branch("0").intern()),
    NONCE(OIDs.DETACHED_SIGNATURE.branch("1").intern());

    /**
     * Sign the `plaintext` and return the CMS SignedData serialized.
     */
    fun sign(
        plaintext: ByteArray,
        privateKey: PrivateKey,
        signerCertificate: Certificate
    ): ByteArray {
        val safePlaintext = makePlaintextSafe(plaintext)
        val signedData = SignedData.sign(
            safePlaintext,
            privateKey,
            signerCertificate,
            encapsulatedCertificates = setOf(signerCertificate),
            encapsulatePlaintext = false
        )
        return signedData.serialize()
    }

    /**
     * Verify `signatureSerialized` and return the signer's certificate if valid.
     */
    @Throws(InvalidSignatureException::class)
    fun verify(
        signatureSerialized: ByteArray,
        expectedPlaintext: ByteArray,
        trustedCertificates: List<Certificate>
    ): Certificate {
        val safePlaintext = makePlaintextSafe(expectedPlaintext)
        val signedData = try {
            SignedData.deserialize(signatureSerialized).also { it.verify(safePlaintext) }
        } catch (exc: SignedDataException) {
            throw InvalidSignatureException("SignedData value is invalid", exc)
        }
        val signerCertificate = signedData.signerCertificate!!
        try {
            signerCertificate.getCertificationPath(emptyList(), trustedCertificates)
        } catch (exc: CertificateException) {
            throw InvalidSignatureException("Signer is not trusted", exc)
        }
        return signerCertificate
    }

    private fun makePlaintextSafe(plaintext: ByteArray) = ASN1Utils.serializeSequence(
        arrayOf(oid, DEROctetString(plaintext)),
        false
    )
}
