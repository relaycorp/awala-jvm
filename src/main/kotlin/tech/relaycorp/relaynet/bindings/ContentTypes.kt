package tech.relaycorp.relaynet.bindings

/**
 * Content types used by bindings.
 */
@Suppress("unused")
enum class ContentTypes(val value: String) {
    PARCEL("application/vnd.relaynet.parcel"),

    NODE_REGISTRATION_AUTHORIZATION("application/vnd.relaynet.node-registration.authorization"),
    NODE_REGISTRATION_REQUEST("application/vnd.relaynet.node-registration.request"),
    NODE_REGISTRATION("application/vnd.relaynet.node-registration.registration"),
    NODE_PRE_REGISTRATION("text/plain")
}
