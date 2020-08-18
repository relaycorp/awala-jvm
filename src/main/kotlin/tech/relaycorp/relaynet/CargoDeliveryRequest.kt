package tech.relaycorp.relaynet

import java.io.InputStream

/**
 * Cargo Delivery Request.
 *
 * A reference to a local cargo which is to be delivered by cargo relay binding like CogRPC.
 *
 * @param localId The path, database PK or any other identifier for the cargo
 * @param cargoSerialized The cargo itself
 */
public data class CargoDeliveryRequest(val localId: String, val cargoSerialized: () -> InputStream)
