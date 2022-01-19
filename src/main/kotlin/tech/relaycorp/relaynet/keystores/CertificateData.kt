package tech.relaycorp.relaynet.keystores

import java.time.ZonedDateTime
import tech.relaycorp.relaynet.wrappers.x509.Certificate

data class CertificateData(
    val expiryDate: ZonedDateTime,
    val der: ByteArray
)