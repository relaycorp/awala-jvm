package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException

abstract class CertificateStore {

    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        certificationPath: CertificationPath,
        issuerPrivateAddress: String
    ) {
        if (certificationPath.leafCertificate.expiryDate < ZonedDateTime.now()) return

        saveData(
            certificationPath.leafCertificate.subjectId,
            certificationPath.leafCertificate.expiryDate,
            certificationPath.serialize(),
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
