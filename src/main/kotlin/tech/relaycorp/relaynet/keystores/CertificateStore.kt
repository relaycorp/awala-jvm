package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException

abstract class CertificateStore {

    @Throws(KeyStoreBackendException::class)
    suspend fun save(
        certificationPath: CertificationPath,
        issuerId: String
    ) {
        if (certificationPath.leafCertificate.expiryDate < ZonedDateTime.now()) return

        saveData(
            certificationPath.leafCertificate.subjectId,
            certificationPath.leafCertificate.expiryDate,
            certificationPath.serialize(),
            issuerId
        )
    }

    protected abstract suspend fun saveData(
        subjectId: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray,
        issuerId: String,
    )

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveLatest(
        subjectId: String,
        issuerId: String
    ): CertificationPath? =
        retrieveAll(subjectId, issuerId)
            .maxByOrNull { it.leafCertificate.expiryDate }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAll(
        subjectId: String,
        issuerId: String
    ): List<CertificationPath> = try {
        retrieveData(subjectId, issuerId)
            .map { CertificationPath.deserialize(it) }
            .filter { it.leafCertificate.expiryDate >= ZonedDateTime.now() }
    } catch (exc: CertificationPathException) {
        throw KeyStoreBackendException("Stored certification path is malformed", exc)
    }

    protected abstract suspend fun retrieveData(
        subjectId: String,
        issuerId: String
    ): List<ByteArray>

    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteExpired()

    @Throws(KeyStoreBackendException::class)
    abstract fun delete(subjectId: String, issuerId: String)
}
