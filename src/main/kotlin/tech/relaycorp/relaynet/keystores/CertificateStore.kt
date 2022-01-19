package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERSequence
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.x509.Certificate

abstract class CertificateStore {

    @Throws(KeyStoreBackendException::class)
    suspend fun save(certificate: Certificate, chain: List<Certificate> = emptyList()) {
        if (certificate.expiryDate < ZonedDateTime.now()) return

        saveData(
            certificate.subjectPrivateAddress,
            certificate.expiryDate,
            CertificationPath(certificate, chain).toData()
        )
    }

    protected abstract suspend fun saveData(
        subjectPrivateAddress: String,
        leafCertificateExpiryDate: ZonedDateTime,
        certificationPathData: ByteArray
    )

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveLatest(subjectPrivateAddress: String): CertificationPath? =
        retrieveAll(subjectPrivateAddress)
            .maxByOrNull { it.leafCertificate.expiryDate }

    @Throws(KeyStoreBackendException::class)
    suspend fun retrieveAll(subjectPrivateAddress: String): List<CertificationPath> =
        retrieveData(subjectPrivateAddress)
            .map { it.toCertificationPath() }
            .filter { it.leafCertificate.expiryDate < ZonedDateTime.now() }

    protected abstract suspend fun retrieveData(
        subjectPrivateAddress: String
    ): List<ByteArray>

    @Throws(KeyStoreBackendException::class)
    abstract suspend fun deleteExpired()

    @Throws(KeyStoreBackendException::class)
    abstract fun delete(subjectPrivateAddress: String)

    // Helpers

    private fun CertificationPath.toData() =
        ASN1Utils.serializeSequence(
            listOf(leafCertificate.toASN1()) + chain.map { it.toASN1() },
            false
        )

    private fun Certificate.toASN1() =
        certificateHolder.toASN1Structure()

    private fun ByteArray.toCertificationPath(): CertificationPath {
        val pathEncoded = ASN1Utils.deserializeHeterogeneousSequence(this)

        val leafCertificate = pathEncoded.first().encoded.toCertificate()

        val chainEncoded = DERSequence.getInstance(pathEncoded[1], false)
        val chain = chainEncoded.objects.asSequence().toList()
            .map { (it as ASN1TaggedObject).encoded.toCertificate() }

        return CertificationPath(leafCertificate, chain)
    }

    private fun ByteArray.toCertificate() =
        Certificate.deserialize(this)
}