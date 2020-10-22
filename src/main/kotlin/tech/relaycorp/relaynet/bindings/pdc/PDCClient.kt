package tech.relaycorp.relaynet.bindings.pdc

import kotlinx.coroutines.flow.Flow
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistration
import tech.relaycorp.relaynet.messages.control.PrivateNodeRegistrationRequest
import java.io.Closeable
import java.security.PublicKey

/**
 * Interface for all Parcel Delivery Connection clients.
 */
interface PDCClient : Closeable {
    /**
     * Request a Private Node Registration Authorization (PNRA).
     *
     * @param nodePublicKey The public key of the private node requesting authorization
     */
    @Throws(
        ServerException::class,
        ClientBindingException::class
    )
    suspend fun preRegisterNode(nodePublicKey: PublicKey): PrivateNodeRegistrationRequest

    /**
     * Register a private node.
     *
     * @param pnrrSerialized The Private Node Registration Request
     */
    @Throws(
        ServerException::class,
        ClientBindingException::class
    )
    suspend fun registerNode(pnrrSerialized: ByteArray): PrivateNodeRegistration

    /**
     * Deliver a parcel.
     *
     * @param parcelSerialized The serialization of the parcel
     * @param deliverySigner The signer to sign this delivery
     */
    @Throws(
        ServerException::class,
        RejectedParcelException::class,
        ClientBindingException::class
    )
    suspend fun deliverParcel(parcelSerialized: ByteArray, deliverySigner: Signer)

    /**
     * Collect parcels on behalf of the specified nodes.
     *
     * @param nonceSigners The nonce signers for each node whose parcels should be collected
     * @param streamingMode Which streaming mode to ask the server to use
     */
    @Throws(
        ServerException::class,
        NonceSignerException::class,
        ClientBindingException::class
    )
    suspend fun collectParcels(
        nonceSigners: Array<Signer>,
        streamingMode: StreamingMode = StreamingMode.KeepAlive
    ): Flow<ParcelCollection>
}
