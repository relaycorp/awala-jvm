package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
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
    { r: Recipient, p: ByteArray, s: Certificate -> Cargo(r, p, s) },
    0x43,
    0x00,
    Cargo.Companion,
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
                CDACertPath.PRIVATE_GW.subjectId,
                CDACertPath.INTERNET_GW.subjectId,
            )
        }

    @Test
    fun `Payload deserialization should be delegated to CargoMessageSet`() =
        runTest {
            val cargoMessageSet =
                CargoMessageSet(arrayOf("msg1".toByteArray(), "msg2".toByteArray()))
            val cargo =
                Cargo(
                    Recipient(CDACertPath.PRIVATE_GW.subjectId),
                    cargoMessageSet.encrypt(
                        recipientSessionKeyPair.sessionKey,
                        senderSessionKeyPair,
                    ),
                    CDACertPath.INTERNET_GW,
                )

            val (payloadDeserialized) = cargo.unwrapPayload(privateKeyStore)

            assertEquals(
                cargoMessageSet.messages.map { it.asList() },
                payloadDeserialized.messages.map { it.asList() },
            )
        }
}
