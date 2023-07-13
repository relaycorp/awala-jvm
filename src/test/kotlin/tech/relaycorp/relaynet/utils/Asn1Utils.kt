package tech.relaycorp.relaynet.utils

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DLTaggedObject

fun ASN1Encodable.toImplicitlyTaggedObject() = DLTaggedObject(false, 1, this)
fun ASN1Encodable.toExplicitlyTaggedObject() = DLTaggedObject(true, 1, this)
