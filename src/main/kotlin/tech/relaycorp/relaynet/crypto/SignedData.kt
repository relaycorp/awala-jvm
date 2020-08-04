package tech.relaycorp.relaynet.crypto

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
import java.io.IOException
import java.security.PrivateKey

/**
 * Relaynet-specific, CMS SignedData representation.
 */
class SignedData(internal val bcSignedData: CMSSignedData) {
    val plaintext: ByteArray? by lazy { bcSignedData.signedContent?.content as ByteArray? }

    val signerCertificate: X509CertificateHolder by lazy {
        // We shouldn't have to force this type cast but this is the only way I could get the code to work and, based on
        // what I found online, that's what others have had to do as well
        @Suppress("UNCHECKED_CAST") val signerCertSelector = X509CertificateHolderSelector(
            signerInfo.sid.issuer,
            signerInfo.sid.serialNumber
        ) as Selector<X509CertificateHolder>

        val signerCertMatches = bcSignedData.certificates.getMatches(signerCertSelector)
        try {
            signerCertMatches.first()
        } catch (_: NoSuchElementException) {
            throw SignedDataException("Certificate of signer should be attached")
        }
    }

    val attachedCertificates: Set<X509CertificateHolder> by lazy {
        (bcSignedData.certificates as CollectionStore).toSet()
    }

    fun serialize(): ByteArray = bcSignedData.encoded

    fun verify() {
        if (plaintext == null) {
            throw SignedDataException("Signed plaintext should be encapsulated")
        }
        val verifier = JcaSimpleSignerInfoVerifierBuilder()
            .setProvider(BC_PROVIDER)
            .build(signerCertificate)
        try {
            signerInfo.verify(verifier)
        } catch (_: CMSException) {
            throw SignedDataException("Invalid signature")
        }
    }

    private val signerInfo: SignerInformation by lazy {
        val signersCount = bcSignedData.signerInfos.size()
        if (signersCount != 1) {
            throw SignedDataException(
                "SignedData should contain exactly one SignerInfo (got $signersCount)"
            )
        }
        bcSignedData.signerInfos.first()
    }

    companion object {
        private val signatureAlgorithmMap = mapOf(
            HashingAlgorithm.SHA256 to "SHA256WITHRSAANDMGF1",
            HashingAlgorithm.SHA384 to "SHA384WITHRSAANDMGF1",
            HashingAlgorithm.SHA512 to "SHA512WITHRSAANDMGF1"
        )

        @JvmStatic
        fun sign(
            plaintext: ByteArray,
            signerPrivateKey: PrivateKey,
            signerCertificate: X509CertificateHolder,
            caCertificates: Set<X509CertificateHolder> = setOf(),
            hashingAlgorithm: HashingAlgorithm? = null
        ): SignedData {
            val signedDataGenerator = CMSSignedDataGenerator()

            val algorithm = hashingAlgorithm ?: HashingAlgorithm.SHA256
            val signerBuilder =
                JcaContentSignerBuilder(signatureAlgorithmMap[algorithm]).setProvider(BC_PROVIDER)
            val contentSigner: ContentSigner = signerBuilder.build(signerPrivateKey)
            val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
                JcaDigestCalculatorProviderBuilder()
                    .build()
            ).build(contentSigner, signerCertificate)
            signedDataGenerator.addSignerInfoGenerator(
                signerInfoGenerator
            )

            val certs = JcaCertStore(
                listOf(signerCertificate, *caCertificates.toTypedArray())
            )
            signedDataGenerator.addCertificates(certs)

            val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
            val bcSignedData = signedDataGenerator.generate(plaintextCms, true)
            return SignedData(bcSignedData)
        }

        @JvmStatic
        fun deserialize(serialization: ByteArray): SignedData {
            val asn1Stream = ASN1InputStream(serialization)
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
            val bcSignedData = try {
                CMSSignedData(contentInfo)
            } catch (_: CMSException) {
                throw SignedDataException("ContentInfo wraps invalid SignedData value")
            }
            return SignedData(bcSignedData)
        }
    }
}
