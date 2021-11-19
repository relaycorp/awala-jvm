package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
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
        { r: String, p: ByteArray, s: Certificate -> CargoCollectionAuthorization(r, p, s) },
        0x44,
        0x00,
        CargoCollectionAuthorization.Companion
    ) {
    private val recipientSessionKeyPair = SessionKeyPair.generate()
    private val senderSessionKeyPair = SessionKeyPair.generate()

    private val privateKeyStore = MockPrivateKeyStore()

    @BeforeEach
    fun registerSessionKey() = runBlockingTest {
        privateKeyStore.saveSessionKey(
            recipientSessionKeyPair.privateKey,
            recipientSessionKeyPair.sessionKey.keyId,
            CDACertPath.PRIVATE_GW.subjectPrivateAddress,
            CDACertPath.PUBLIC_GW.subjectPrivateAddress,
        )
    }

    @Test
    fun `Payload deserialization should be delegated to CargoCollectionRequest`() =
        runBlockingTest {
            val ccr = CargoCollectionRequest(CDACertPath.PUBLIC_GW)
            val cca = CargoCollectionAuthorization(
                CDACertPath.PUBLIC_GW.subjectPrivateAddress,
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
