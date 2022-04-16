package tech.relaycorp.relaynet.messages

import tech.relaycorp.relaynet.pki.CertificationPath
import tech.relaycorp.relaynet.pki.CertificationPathException

class CertificateRotation(val certificationPath: CertificationPath) {
    fun serialize(): ByteArray = FORMAT_SIGNATURE + certificationPath.serialize()

    companion object {
        private const val concreteMessageType: Byte = 0x10
        private const val concreteMessageVersion: Byte = 0
        internal val FORMAT_SIGNATURE = byteArrayOf(
            *"Relaynet".toByteArray(),
            concreteMessageType,
            concreteMessageVersion
        )

        @Throws(InvalidMessageException::class)
        fun deserialize(serialization: ByteArray): CertificateRotation {
            if (serialization.size < FORMAT_SIGNATURE.size) {
                throw InvalidMessageException("Message is too short to contain format signature")
            }
            val formatSignature = serialization.slice(FORMAT_SIGNATURE.indices)
            if (formatSignature != FORMAT_SIGNATURE.asList()) {
                throw InvalidMessageException(
                    "Format signature is not that of a CertificateRotation"
                )
            }

            val certificationPathSerialized =
                serialization.sliceArray(FORMAT_SIGNATURE.size until serialization.size)
            val certificationPath = try {
                CertificationPath.deserialize(certificationPathSerialized)
            } catch (exc: CertificationPathException) {
                throw InvalidMessageException("CertificationPath is malformed", exc)
            }

            return CertificateRotation(certificationPath)
        }
    }
}
