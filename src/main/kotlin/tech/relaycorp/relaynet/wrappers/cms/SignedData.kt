package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.selector.X509CertificateHolderSelector
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.CollectionStore
import org.bouncycastle.util.Selector
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.HashingAlgorithm
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.IOException
import java.security.PrivateKey

private val signatureAlgorithmMap = mapOf(
    HashingAlgorithm.SHA256 to "SHA256WITHRSAANDMGF1",
    HashingAlgorithm.SHA384 to "SHA384WITHRSAANDMGF1",
    HashingAlgorithm.SHA512 to "SHA512WITHRSAANDMGF1"
)

@Throws(SignedDataException::class)
internal fun sign(
    plaintext: ByteArray,
    signerPrivateKey: PrivateKey,
    signerCertificate: Certificate,
    caCertificates: Set<Certificate> = setOf(),
    hashingAlgorithm: HashingAlgorithm? = null
): ByteArray {
    val signedDataGenerator = CMSSignedDataGenerator()

    val algorithm = hashingAlgorithm ?: HashingAlgorithm.SHA256
    val signerBuilder =
        JcaContentSignerBuilder(signatureAlgorithmMap[algorithm]).setProvider(BC_PROVIDER)
    val contentSigner: ContentSigner = signerBuilder.build(signerPrivateKey)
    val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
        JcaDigestCalculatorProviderBuilder()
            .build()
    ).build(contentSigner, signerCertificate.certificateHolder)
    signedDataGenerator.addSignerInfoGenerator(
        signerInfoGenerator
    )

    val caCertHolders = caCertificates.map { c -> c.certificateHolder }
    val certs = JcaCertStore(
        listOf(
            signerCertificate.certificateHolder,
            *caCertHolders.toTypedArray()
        )
    )
    signedDataGenerator.addCertificates(certs)

    val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
    val cmsSignedData = signedDataGenerator.generate(plaintextCms, true)
    return cmsSignedData.encoded
}

@Suppress("ArrayInDataClass")
internal data class SignatureVerification(
    val plaintext: ByteArray,
    val signerCertificate: Certificate,
    val attachedCertificates: Set<Certificate>
)

@Throws(SignedDataException::class)
internal fun verifySignature(cmsSignedData: ByteArray): SignatureVerification {
    val signedData = parseCmsSignedData(cmsSignedData)

    val signerInfo = getSignerInfoFromSignedData(signedData)

    // We shouldn't have to force this type cast but this is the only way I could get the code to work and, based on
    // what I found online, that's what others have had to do as well
    @Suppress("UNCHECKED_CAST") val signerCertSelector = X509CertificateHolderSelector(
        signerInfo.sid.issuer,
        signerInfo.sid.serialNumber
    ) as Selector<X509CertificateHolder>

    val signerCertMatches = signedData.certificates.getMatches(signerCertSelector)
    val signerCertificateHolder = try {
        signerCertMatches.first()
    } catch (_: NoSuchElementException) {
        throw SignedDataException(
            "Certificate of signer should be attached"
        )
    }
    val verifier = JcaSimpleSignerInfoVerifierBuilder()
        .setProvider(BC_PROVIDER)
        .build(signerCertificateHolder)
    try {
        signerInfo.verify(verifier)
    } catch (_: CMSException) {
        throw SignedDataException("Invalid signature")
    }

    val attachedCerts = (signedData.certificates as CollectionStore).asSequence()
    return SignatureVerification(
        signedData.signedContent.content as ByteArray,
        Certificate(signerCertificateHolder),
        attachedCerts.map { Certificate(it) }.toSet()
    )
}

private fun getSignerInfoFromSignedData(signedData: CMSSignedData): SignerInformation {
    if (signedData.signedContent == null) {
        throw SignedDataException("Signed plaintext should be encapsulated")
    }

    val signersCount = signedData.signerInfos.size()
    if (signersCount != 1) {
        throw SignedDataException(
            "SignedData should contain exactly one SignerInfo (got $signersCount)"
        )
    }
    return signedData.signerInfos.first()
}

@Throws(SignedDataException::class)
private fun parseCmsSignedData(cmsSignedDataSerialized: ByteArray): CMSSignedData {
    val asn1Stream = ASN1InputStream(cmsSignedDataSerialized)
    val asn1Sequence = try {
        asn1Stream.readObject()
    } catch (_: IOException) {
        throw SignedDataException("Value is not DER-encoded")
    }
    val contentInfo = try {
        ContentInfo.getInstance(asn1Sequence)
    } catch (_: IllegalArgumentException) {
        throw SignedDataException("SignedData value is not wrapped in ContentInfo")
    }
    return try {
        CMSSignedData(contentInfo)
    } catch (_: CMSException) {
        throw SignedDataException("ContentInfo wraps invalid SignedData value")
    }
}
