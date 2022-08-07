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
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray,
        issuerPrivateAddress: String
    ) {
        if (savingException != null) {
            throw KeyStoreBackendException("Saving certificates isn't supported", savingException)
        }
        data[subjectPrivateAddress to issuerPrivateAddress] =
            data[subjectPrivateAddress to issuerPrivateAddress].orEmpty() +
            listOf(Pair(leafCertificateExpiryDate, certificationPathData))
    }

    suspend fun forceSave(
        certificationPath: CertificationPath,
        issuerPrivateAddress: String
    ) {
        saveData(
            certificationPath.leafCertificate.subjectPrivateAddress,
            certificationPath.leafCertificate.expiryDate,
            certificationPath.serialize(),
            issuerPrivateAddress
        )
    }

    override suspend fun retrieveData(
        subjectPrivateAddress: String,
        issuerPrivateAddress: String
    ): List<ByteArray> {
        if (retrievalException != null) {
            throw KeyStoreBackendException(
                "Retrieving certificates isn't supported",
                retrievalException
            )
        }
        return data[subjectPrivateAddress to issuerPrivateAddress].orEmpty().map { it.second }
    }

    override suspend fun deleteExpired() {
        data.forEach { (key, pairs) ->
            data[key] = pairs.filter { it.first >= ZonedDateTime.now() }
        }
    }

    override fun delete(subjectPrivateAddress: String, issuerPrivateAddress: String) {
        data.remove(subjectPrivateAddress to issuerPrivateAddress)
    }
}
