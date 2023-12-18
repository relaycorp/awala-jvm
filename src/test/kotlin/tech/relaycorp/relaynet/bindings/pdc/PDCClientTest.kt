package tech.relaycorp.relaynet.bindings.pdc

import java.security.PublicKey
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistration
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistrationRequest

class MockPDCClient : PDCClient {
    var parcelsCollected = false

    override fun close() = throw NotImplementedError()

    override suspend fun preRegisterNode(nodePublicKey: PublicKey): PrivateNodeRegistrationRequest =
        throw NotImplementedError()

    override suspend fun registerNode(pnrrSerialized: ByteArray): PrivateNodeRegistration =
        throw NotImplementedError()

    override suspend fun deliverParcel(
        parcelSerialized: ByteArray,
        deliverySigner: Signer,
    ) = throw NotImplementedError()

    override suspend fun collectParcels(
        nonceSigners: Array<Signer>,
        streamingMode: StreamingMode,
    ): Flow<ParcelCollection> =
        flow {
            parcelsCollected = true
        }
}

@ExperimentalCoroutinesApi
class PDCClientTest {
    @Test
    fun `Parcels can be collected without a explicit streaming mode`() =
        runTest {
            val client = MockPDCClient()

            client.collectParcels(emptyArray()).toList()

            assertTrue(client.parcelsCollected)
        }
}
