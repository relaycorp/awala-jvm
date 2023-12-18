package tech.relaycorp.relaynet.utils

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.keystores.CertificateStore
import tech.relaycorp.relaynet.keystores.KeyStoreBackendException
import tech.relaycorp.relaynet.pki.CertificationPath

class MockCertificateStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : CertificateStore() {
    val data: MutableMap<Pair<String, String>, List<Pair<ZonedDateTime, ByteArray>>> =
        mutableMapOf()

    override suspend fun saveData(
        subjectId: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray,
        issuerId: String,
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving certificates isn't supported", savingException)
        }
        data[subjectId to issuerId] =
            data[subjectId to issuerId].orEmpty() +
            listOf(Pair(leafCertificateExpiryDate, certificationPathData))
    }

    suspend fun forceSave(
        certificationPath: CertificationPath,
        issuerId: String,
    ) {
        saveData(
            certificationPath.leafCertificate.subjectId,
            certificationPath.leafCertificate.expiryDate,
            certificationPath.serialize(),
            issuerId,
        )
    }

    override suspend fun retrieveData(
        subjectId: String,
        issuerId: String,
    ): List<ByteArray> {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving certificates isn't supported",
                retrievalException,
            )
        }
        return data[subjectId to issuerId].orEmpty().map { it.second }
    }

    override suspend fun deleteExpired() {
        data.forEach { (key, pairs) ->
            data[key] = pairs.filter { it.first >= ZonedDateTime.now() }
        }
    }

    override fun delete(
        subjectId: String,
        issuerId: String,
    ) {
        data.remove(subjectId to issuerId)
    }
}
