package tech.relaycorp.relaynet.messages

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.ramf.generateConstructorTests
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import kotlin.test.assertEquals

class CargoCollectionAuthorizationTest {
    @TestFactory
    fun makeConstructorTests() =
        generateConstructorTests(::CargoCollectionAuthorization, 0x51, 0x00)

    @Nested
    inner class Companion {
        @Nested
        inner class Deserialize {
            private val recipientAddress = "0deadbeef"
            private val payload = "Payload".toByteArray()
            private val keyPair = generateRSAKeyPair()
            private val senderCertificate = issueStubCertificate(keyPair.public, keyPair.private)

            @Test
            fun `Valid CCAs should be deserialized`() {
                val cca = CargoCollectionAuthorization(recipientAddress, payload, senderCertificate)
                val ccaSerialized = cca.serialize(keyPair.private)

                val ccaDeserialized = CargoCollectionAuthorization.deserialize(ccaSerialized)

                assertEquals(cca.messageId, ccaDeserialized.messageId)
            }
        }
    }
}
