package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.BeforeEach
import tech.relaycorp.relaynet.SessionKeyPair
import tech.relaycorp.relaynet.messages.payloads.CargoMessageSet
import tech.relaycorp.relaynet.ramf.RAMFSpecializationTestCase
import tech.relaycorp.relaynet.utils.CDACertPath
import tech.relaycorp.relaynet.utils.MockPrivateKeyStore
import tech.relaycorp.relaynet.wrappers.x509.Certificate

@ExperimentalCoroutinesApi
internal class CargoTest : RAMFSpecializationTestCase<Cargo>(
    ::Cargo,
    { r: String, p: ByteArray, s: Certificate -> Cargo(r, p, s) },
    0x43,
    0x00,
    Cargo.Companion
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
    fun `Payload deserialization should be delegated to CargoMessageSet`() = runBlockingTest {
        val cargoMessageSet = CargoMessageSet(arrayOf("msg1".toByteArray(), "msg2".toByteArray()))
        val cargo = Cargo(
            CDACertPath.PRIVATE_GW.subjectPrivateAddress,
            cargoMessageSet.encrypt(recipientSessionKeyPair.sessionKey, senderSessionKeyPair),
            CDACertPath.PUBLIC_GW
        )

        val (payloadDeserialized) = cargo.unwrapPayload(privateKeyStore)

        assertEquals(
            cargoMessageSet.messages.map { it.asList() },
            payloadDeserialized.messages.map { it.asList() }
        )
    }
}
