package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.messages.payloads.ServiceMessage
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.utils.PDACertPath
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@ExperimentalCoroutinesApi
internal class ParcelTest : RAMFSpecializationTestCase<Parcel>(
    ::Parcel,
    { r: Recipient, p: ByteArray, s: Certificate -> Parcel(r, p, s) },
    0x50,
    0x00,
    Parcel.Companion,
) {
    private val recipientSessionKeyPair = SessionKeyPair.generate()
    private val senderSessionKeyPair = SessionKeyPair.generate()

    private val privateKeyStore = MockPrivateKeyStore()

    @BeforeEach
    fun registerSessionKey() =
        runTest {
            privateKeyStore.saveSessionKey(
                recipientSessionKeyPair.privateKey,
                recipientSessionKeyPair.sessionKey.keyId,
                PDACertPath.PRIVATE_ENDPOINT.subjectId,
                PDACertPath.PDA.subjectId,
            )
        }

    @Test
    fun `Payload deserialization should be delegated to ServiceMessage`() =
        runTest {
            val serviceMessage = ServiceMessage("the type", "the content".toByteArray())
            val parcel =
                Parcel(
                    Recipient(PDACertPath.PRIVATE_ENDPOINT.subjectId),
                    serviceMessage.encrypt(
                        recipientSessionKeyPair.sessionKey,
                        senderSessionKeyPair,
                    ),
                    PDACertPath.PDA,
                )

            val (serviceMessageDeserialized) = parcel.unwrapPayload(privateKeyStore)

            assertEquals(serviceMessage.type, serviceMessageDeserialized.type)
            assertEquals(
                serviceMessage.content.asList(),
                serviceMessageDeserialized.content.asList(),
            )
        }
}
