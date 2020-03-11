package tech.relaycorp.relaynet.cms

import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import tech.relaycorp.relaynet.x509.Certificate
import tech.relaycorp.relaynet.x509.FullCertificateIssuanceOptions
import tech.relaycorp.relaynet.x509.Keys
import java.io.File
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Security

fun generateStubCert(keyPair: KeyPair): Certificate {
    val commonName = Certificate.buildX500Name("The C Name")
    return Certificate.issue(
        FullCertificateIssuanceOptions(
            commonName,
            keyPair.private,
            keyPair.public,
            issuerCertificate = null
        )
    )
}

@Throws(SignedDataException::class)
fun sign2(plaintext: ByteArray, privateKey: PrivateKey, certificate: Certificate): ByteArray {
    val signedDataGenerator = CMSSignedDataGenerator()

    val contentSigner: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(privateKey)
    val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
        JcaDigestCalculatorProviderBuilder()
            .build()
    ).build(contentSigner, certificate.certificateHolder)
    signedDataGenerator.addSignerInfoGenerator(
        signerInfoGenerator
    )

    val certs = JcaCertStore(listOf(certificate.certificateHolder))
    signedDataGenerator.addCertificates(certs)

    val plaintextCms: CMSTypedData = CMSProcessableByteArray(plaintext)
    val cmsSignedData = signedDataGenerator.generate(plaintextCms, true)
    return cmsSignedData.encoded
}

fun main() {
    Security.addProvider(BouncyCastleProvider())

    val stubKeyPair = Keys.generateRSAKeyPair(2048)
    val certificate = generateStubCert(stubKeyPair)

    val signedData = sign2(
        byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte()),
        stubKeyPair.private,
        certificate
    )

    println("hey")
    println(certificate.certificateHolder.toString())

    File(System.getProperty("user.home") + "/tmp/signed.der").writeBytes(signedData)
}
