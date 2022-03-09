package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1TaggedObject
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class CertificateStore {

    enum class Scope(val value: String) {
        PDA("pda"),
        CDA("cda")
    }

    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        scope: Scope,
        certificate: Certificate,
        chain: List<Certificate> = emptyList()
    ) {
        if (certificate.expiryDate < ZonedDateTime.now()) return

        saveData(
            scope,
            certificate.subjectPrivateAddress,
            certificate.expiryDate,
            CertificationPath(certificate, chain).toData()
        )
    }

    protected abstract suspend fun saveData(
        scope: Scope,
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray,
    )

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveLatest(scope: Scope, subjectPrivateAddress: String): CertificationPath? =
        retrieveAll(scope, subjectPrivateAddress)
            .maxByOrNull { it.leafCertificate.expiryDate }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAll(scope: Scope, subjectPrivateAddress: String): List<CertificationPath> =
        retrieveData(scope, subjectPrivateAddress)
            .map { it.toCertificationPath() }
            .filter { it.leafCertificate.expiryDate >= ZonedDateTime.now() }

    protected abstract suspend fun retrieveData(
        scope: Scope,
        subjectPrivateAddress: String
    ): List<ByteArray>

    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteExpired()

    @Throws(KeyStoreBackendException::class)
    abstract fun delete(scope: Scope, subjectPrivateAddress: String)

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
        Certificate.deserialize(`object`.encoded)
}
