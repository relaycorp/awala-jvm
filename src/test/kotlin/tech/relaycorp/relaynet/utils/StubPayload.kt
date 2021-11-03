package tech.relaycorp.relaynet.utils

import java.nio.charset.Charset
import tech.relaycorp.relaynet.messages.payloads.Payload

class StubPayload(val payload: String) : Payload {
    override fun serializePlaintext() = payload.toByteArray()

    companion object {
        fun deserialize(serialization: ByteArray) =
            StubPayload(serialization.toString(Charset.defaultCharset()))
    }
}
