package tech.relaycorp.relaynet.utils

import java.time.format.DateTimeFormatter
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive

fun parseDer(derSerialization: ByteArray): ASN1Primitive {
    val asn1Stream = ASN1InputStream(derSerialization)
    return asn1Stream.readObject()
}

val BER_DATETIME_FORMATTER: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyyMMddHHmmss")
