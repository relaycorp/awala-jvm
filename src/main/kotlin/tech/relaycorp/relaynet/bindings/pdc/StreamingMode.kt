package tech.relaycorp.relaynet.bindings.pdc

enum class StreamingMode(val headerValue: String) {
    KeepAlive("keep-alive"),
    CloseUponCompletion("close-upon-completion");

    companion object {
        const val HEADER_NAME = "X-Relaynet-Streaming-Mode"
    }
}
