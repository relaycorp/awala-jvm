package tech.relaycorp.relaynet.bindings.pdc

import kotlinx.coroutines.flow.Flow
import java.io.Closeable

/**
 * Interface for all Parcel Delivery Connection clients.
 */
interface PDCClient : Closeable {
    suspend fun deliverParcel(parcelSerialized: ByteArray)

    suspend fun collectParcels(
        nonceSigners: Array<NonceSigner>,
        streamingMode: StreamingMode = StreamingMode.KeepAlive
    ): Flow<ParcelCollection>
}
