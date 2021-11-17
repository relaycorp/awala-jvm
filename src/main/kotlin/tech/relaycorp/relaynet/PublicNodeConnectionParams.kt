package tech.relaycorp.relaynet

import java.security.PublicKey
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERVisibleString
import tech.relaycorp.relaynet.wrappers.DNS
import tech.relaycorp.relaynet.wrappers.KeyException
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.deserializeECPublicKey
import tech.relaycorp.relaynet.wrappers.deserializeRSAPublicKey

class PublicNodeConnectionParams(
    val publicAddress: String,
    val identityKey: PublicKey,
    val sessionKey: SessionKey
) {
    fun serialize(): ByteArray {
        val sessionKeyASN1 = ASN1Utils.makeSequence(
            listOf(
                DEROctetString(sessionKey.keyId),
                DEROctetString(sessionKey.publicKey.encoded)
            ),
            false
        )
        return ASN1Utils.serializeSequence(
            listOf(
                DERVisibleString(publicAddress),
                DEROctetString(identityKey.encoded),
                sessionKeyASN1
            ),
            false
        )
    }

    companion object {
        @Throws(InvalidNodeConnectionParams::class)
        fun deserialize(serialization: ByteArray): PublicNodeConnectionParams {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidNodeConnectionParams("Serialization is not a DER sequence", exc)
            }

            if (sequence.size < 3) {
                throw InvalidNodeConnectionParams(
                    "Connection params sequence should have at least 3 items " +
                        "(got ${sequence.size})"
                )
            }

            val publicAddress = ASN1Utils.getVisibleString(sequence[0]).string
            if (!DNS.isValidDomainName(publicAddress)) {
                throw InvalidNodeConnectionParams(
                    "Public address is syntactically invalid ($publicAddress)"
                )
            }

            val identityKeyASN1 = ASN1Utils.getOctetString(sequence[1])
            val identityKey = try {
                identityKeyASN1.octets.deserializeRSAPublicKey()
            } catch (exc: KeyException) {
                throw InvalidNodeConnectionParams(
                    "Identity key is not a valid RSA public key",
                    exc
                )
            }

            val sessionKeySequence = DERSequence.getInstance(sequence[2], false)
            if (sessionKeySequence.size() < 2) {
                throw InvalidNodeConnectionParams(
                    "Session key sequence should have at least 2 items " +
                        "(got ${sessionKeySequence.size()})"
                )
            }

            val sessionKeyId = ASN1Utils.getOctetString(
                sessionKeySequence.getObjectAt(0) as ASN1TaggedObject,
            ).octets

            val sessionPublicKeyASN1 =
                ASN1Utils.getOctetString(sessionKeySequence.getObjectAt(1) as ASN1TaggedObject)
            val sessionPublicKey = try {
                sessionPublicKeyASN1.octets.deserializeECPublicKey()
            } catch (exc: KeyException) {
                throw InvalidNodeConnectionParams(
                    "Session key is not a valid EC public key",
                    exc
                )
            }

            return PublicNodeConnectionParams(
                publicAddress,
                identityKey,
                SessionKey(sessionKeyId, sessionPublicKey)
            )
        }
    }
}
