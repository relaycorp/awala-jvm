package tech.relaycorp.relaynet.bindings

/**
 * Content types used by bindings.
 */
@Suppress("unused")
enum class ContentTypes(val value: String) {
    PARCEL("application/vnd.awala.parcel"),

    NODE_REGISTRATION_AUTHORIZATION("application/vnd.awala.node-registration.authorization"),
    NODE_REGISTRATION_REQUEST("application/vnd.awala.node-registration.request"),
    NODE_REGISTRATION("application/vnd.awala.node-registration.registration"),
    NODE_PRE_REGISTRATION("text/plain")
}
