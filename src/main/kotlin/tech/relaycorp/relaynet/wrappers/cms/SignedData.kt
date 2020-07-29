package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.selector.X509CertificateHolderSelector
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.util.CollectionStore
import org.bouncycastle.util.Selector
import tech.relaycorp.relaynet.BC_PROVIDER
import tech.relaycorp.relaynet.wrappers.x509.Certificate
import java.io.IOException

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
