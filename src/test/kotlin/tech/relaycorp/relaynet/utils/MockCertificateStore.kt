package tech.relaycorp.relaynet.utils

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.keystores.CertificateStore
import tech.relaycorp.relaynet.keystores.KeyStoreBackendException

class MockCertificateStore(
    private val savingException: Throwable? = null,
    private val retrievalException: Throwable? = null,
) : CertificateStore() {

    val data: MutableMap<Pair<Scope, String>, List<Pair<ZonedDateTime, ByteArray>>> = mutableMapOf()

    override suspend fun saveData(
        scope: Scope,
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving certificates isn't supported", savingException)
        }
        data[scope to subjectPrivateAddress] =
            data[scope to subjectPrivateAddress].orEmpty() +
            listOf(Pair(leafCertificateExpiryDate, certificationPathData))
    }

    override suspend fun retrieveData(
        scope: Scope,
        subjectPrivateAddress: String
    ): List<ByteArray> {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving certificates isn't supported",
                retrievalException
            )
        }
        return data[scope to subjectPrivateAddress].orEmpty().map { it.second }
    }

    override suspend fun deleteExpired() {
        data.forEach { (key, pairs) ->
            data[key] = pairs.filter { it.first >= ZonedDateTime.now() }
        }
    }

    override fun delete(scope: Scope, subjectPrivateAddress: String) {
        data.remove(scope to subjectPrivateAddress)
    }
}
