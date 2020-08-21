package tech.relaycorp.relaynet.bindings.pdc

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class MockPDCClient : PDCClient {
    var parcelsCollected = false

    override fun close() = throw NotImplementedError()
    override suspend fun collectParcels(
        nonceSigners: Array<NonceSigner>,
        streamingMode: StreamingMode
    ): Flow<ParcelCollector> = flow {
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
