package tech.relaycorp.relaynet.wrappers.cms

import java.math.BigInteger

abstract class RecipientIdentifier

/**
 * Serial number of an EnvelopedData recipient's certificate.
 *
 * The issuer is ignored: This is only meant to be used by the recipient so it can look up the
 * corresponding private key to decrypt the content. We could certainly extract the issuer to
 * verify it matches the expected one but, if the id doesn't match any key, decryption
 * won't even be attempted, so there's really no risk from ignoring the issuer.
 */
data class RecipientSerialNumber(val subjectSerialNumber: BigInteger) : RecipientIdentifier()

data class RecipientKeyIdentifier(val id: ByteArray) : RecipientIdentifier()
