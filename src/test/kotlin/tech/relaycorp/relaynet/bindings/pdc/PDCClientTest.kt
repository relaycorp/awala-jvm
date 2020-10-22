package tech.relaycorp.relaynet.bindings.pdc

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistration
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistrationAuthorization
import java.security.PublicKey
import kotlin.test.assertTrue

class MockPDCClient : PDCClient {
    var parcelsCollected = false

    override fun close() = throw NotImplementedError()

    override suspend fun preRegisterNode(
        nodePublicKey: PublicKey
    ): PrivateNodeRegistrationAuthorization = throw NotImplementedError()

    override suspend fun registerNode(pnrrSerialized: ByteArray): PrivateNodeRegistration =
        throw NotImplementedError()

    override suspend fun deliverParcel(parcelSerialized: ByteArray, deliverySigner: Signer) =
        throw NotImplementedError()

    override suspend fun collectParcels(
        nonceSigners: Array<Signer>,
        streamingMode: StreamingMode
    ): Flow<ParcelCollection> = flow {
        parcelsCollected = true
    }
}

@ExperimentalCoroutinesApi
class PDCClientTest {
    @Test
    fun `Parcels can be collected without a explicit streaming mode`() = runBlockingTest {
        val client = MockPDCClient()

        client.collectParcels(emptyArray()).toList()

        assertTrue(client.parcelsCollected)
    }
}
