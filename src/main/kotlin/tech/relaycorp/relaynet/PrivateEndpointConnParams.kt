package tech.relaycorp.relaynet

import java.security.PublicKey
import org.bouncycastle.asn1.DERVisibleString
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException
import tech.relaycorp.relaynet.wrappers.DNS
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import tech.relaycorp.relaynet.wrappers.deserializeRSAPublicKey

class PrivateEndpointConnParams(
    val identityKey: PublicKey,
    val internetGatewayAddress: String,
    val deliveryAuth: CertificationPath,
    val sessionKey: SessionKey
) {
    fun serialize(): ByteArray = ASN1Utils.serializeSequence(
        listOf(
            SubjectPublicKeyInfo.getInstance(identityKey.encoded),
            DERVisibleString(internetGatewayAddress),
            deliveryAuth.encode(),
            sessionKey.encode(),
        ),
        false
    )

    companion object {
        @Throws(InvalidNodeConnectionParams::class)
        fun deserialize(serialization: ByteArray): PrivateEndpointConnParams {
            val sequence = try {
                ASN1Utils.deserializeHeterogeneousSequence(serialization)
            } catch (exc: ASN1Exception) {
                throw InvalidNodeConnectionParams("Serialization is not a DER sequence", exc)
            }

            if (sequence.size < 4) {
                throw InvalidNodeConnectionParams(
                    "Connection params should have at least 4 items"
                )
            }

            val identityKeyInfo = try {
                SubjectPublicKeyInfo.getInstance(sequence[0], false)
            } catch (exc: IllegalStateException) {
                throw InvalidNodeConnectionParams("Invalid identity key", exc)
            }
            val identityKey = identityKeyInfo.encoded.deserializeRSAPublicKey()

            val internetGatewayAddress = ASN1Utils.getVisibleString(sequence[1]).string
            if (!DNS.isValidDomainName(internetGatewayAddress)) {
                throw InvalidNodeConnectionParams(
                    "Internet address is syntactically invalid ($internetGatewayAddress)"
                )
            }

            val deliveryAuth = try {
                CertificationPath.decode(sequence[2])
            } catch (exc: CertificationPathException) {
                throw InvalidNodeConnectionParams("Invalid delivery auth", exc)
            }

            val sessionKey = try {
                SessionKey.decode(sequence[3])
            } catch (exc: SessionKeyException) {
                throw InvalidNodeConnectionParams("Invalid session key", exc)
            }

            return PrivateEndpointConnParams(
                identityKey,
                internetGatewayAddress,
                deliveryAuth,
                sessionKey
            )
        }
    }
}
