package tech.relaycorp.relaynet.bindings

/**
 * Content types used by bindings.
 */
@Suppress("unused")
enum class ContentTypes(val value: String) {
    PARCEL("application/vnd.relaynet.parcel"),
    REGISTRATION_AUTHORIZATION("application/vnd.relaynet.node-registration.authorization"),
    REGISTRATION_REQUEST("application/vnd.relaynet.node-registration.request"),
    REGISTRATION("application/vnd.relaynet.node-registration.registration"),
    PRE_REGISTRATION("text/plain")
}
