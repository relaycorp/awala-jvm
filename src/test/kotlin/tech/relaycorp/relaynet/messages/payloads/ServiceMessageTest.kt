package tech.relaycorp.relaynet.messages.payloads

import org.junit.jupiter.api.Nested
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.Test
import kotlin.test.assertEquals

const val TYPE = "this is the type"
val CONTENT = "this is the content".toByteArray()

internal class ServiceMessageTest {
    @Nested
    inner class SerializePlaintext {
        @Test
        fun `Type should be serialized`() {
            val message = ServiceMessage(TYPE, CONTENT)

            val serialization = message.serializePlaintext()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val typeASN1 = ASN1Utils.getVisibleString(sequence.first())
            assertEquals(TYPE, typeASN1.string)
        }

        @Test
        fun `Content should be serialized`() {
            val message = ServiceMessage(TYPE, CONTENT)

            val serialization = message.serializePlaintext()

            val sequence = ASN1Utils.deserializeHeterogeneousSequence(serialization)
            val contentASN1 = ASN1Utils.getOctetString(sequence[1])
            assertEquals(CONTENT.asList(), contentASN1.octets.asList())
        }
    }
}
