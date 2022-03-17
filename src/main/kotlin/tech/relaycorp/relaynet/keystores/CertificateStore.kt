package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1TaggedObject
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class CertificateStore {

    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        certificate: Certificate,
        chain: List<Certificate> = emptyList(),
        issuerPrivateAddress: String
    ) {
        if (certificate.expiryDate < ZonedDateTime.now()) return

        saveData(
            certificate.subjectPrivateAddress,
            certificate.expiryDate,
            CertificationPath(certificate, chain).toData(),
            issuerPrivateAddress
        )
    }

    protected abstract suspend fun saveData(
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray,
        issuerPrivateAddress: String,
    )

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveLatest(
        subjectPrivateAddress: String,
        issuerPrivateAddress: String
    ): CertificationPath? =
        retrieveAll(subjectPrivateAddress, issuerPrivateAddress)
            .maxByOrNull { it.leafCertificate.expiryDate }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAll(
        subjectPrivateAddress: String,
        issuerPrivateAddress: String
    ): List<CertificationPath> =
        retrieveData(subjectPrivateAddress, issuerPrivateAddress)
            .map { it.toCertificationPath() }
            .filter { it.leafCertificate.expiryDate >= ZonedDateTime.now() }

    protected abstract suspend fun retrieveData(
        subjectPrivateAddress: String,
        issuerPrivateAddress: String
    ): List<ByteArray>

    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteExpired()

    @Throws(KeyStoreBackendException::class)
    abstract fun delete(subjectPrivateAddress: String, issuerPrivateAddress: String)

    // Helpers

    private fun CertificationPath.toData() =
        ASN1Utils.serializeSequence(
            listOf(leafCertificate.toASN1()) + chain.map { it.toASN1() },
            false
        )

    private fun Certificate.toASN1() =
        certificateHolder.toASN1Structure()

    @Throws(KeyStoreBackendException::class)
    private fun ByteArray.toCertificationPath(): CertificationPath {
        val pathEncoded = try {
            ASN1Utils.deserializeHeterogeneousSequence(this)
        } catch (exception: ASN1Exception) {
            throw KeyStoreBackendException("Malformed certification path", exception)
        }

        if (pathEncoded.isEmpty()) {
            throw KeyStoreBackendException("Empty certification path")
        }

        val leafCertificate = pathEncoded[0].toCertificate()
        val chain = pathEncoded.copyOfRange(1, pathEncoded.size).map { it.toCertificate() }

        return CertificationPath(leafCertificate, chain)
    }

    private fun ASN1TaggedObject.toCertificate() =
        Certificate.deserialize(baseObject.encoded)
}
