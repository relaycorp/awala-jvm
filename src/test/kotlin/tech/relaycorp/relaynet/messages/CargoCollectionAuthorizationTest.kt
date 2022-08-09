package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.messages.payloads.CargoCollectionRequest
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.utils.CDACertPath
import tech.relaycorp.relaynet.utils.ID_CERTIFICATE
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@OptIn(ExperimentalCoroutinesApi::class)
internal class CargoCollectionAuthorizationTest :
    RAMFSpecializationTestCase<CargoCollectionAuthorization>(
        ::CargoCollectionAuthorization,
        { r: Recipient, p: ByteArray, s: Certificate -> CargoCollectionAuthorization(r, p, s) },
        0x44,
        0x00,
        CargoCollectionAuthorization.Companion
    ) {
    private val recipientSessionKeyPair = SessionKeyPair.generate()
    private val senderSessionKeyPair = SessionKeyPair.generate()

    private val privateKeyStore = MockPrivateKeyStore()

    @BeforeEach
    fun registerSessionKey() = runTest {
        privateKeyStore.saveSessionKey(
            recipientSessionKeyPair.privateKey,
            recipientSessionKeyPair.sessionKey.keyId,
            CDACertPath.PRIVATE_GW.subjectId,
            CDACertPath.INTERNET_GW.subjectId,
        )
    }

    @Test
    fun `Payload deserialization should be delegated to CargoCollectionRequest`() =
        runTest {
            val ccr = CargoCollectionRequest(CDACertPath.INTERNET_GW)
            val cca = CargoCollectionAuthorization(
                Recipient(CDACertPath.INTERNET_GW.subjectId),
                ccr.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
                ID_CERTIFICATE
            )

            val (payloadDeserialized) = cca.unwrapPayload(recipientSessionKeyPair.privateKey)

            assertEquals(
                ccr.cargoDeliveryAuthorization,
                payloadDeserialized.cargoDeliveryAuthorization
            )
        }
}
