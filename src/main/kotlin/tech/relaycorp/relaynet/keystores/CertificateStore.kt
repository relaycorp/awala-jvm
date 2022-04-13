package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
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
            CertificationPath(certificate, chain).serialize(),
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
    ): List<CertificationPath> = try {
        retrieveData(subjectPrivateAddress, issuerPrivateAddress)
            .map { CertificationPath.deserialize(it) }
            .filter { it.leafCertificate.expiryDate >= ZonedDateTime.now() }
    } catch (exc: CertificationPathException) {
        throw KeyStoreBackendException("Stored certification path is malformed", exc)
    }

    protected abstract suspend fun retrieveData(
        subjectPrivateAddress: String,
        issuerPrivateAddress: String
    ): List<ByteArray>

    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteExpired()

    @Throws(KeyStoreBackendException::class)
    abstract fun delete(subjectPrivateAddress: String, issuerPrivateAddress: String)
}
