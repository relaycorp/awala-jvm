package tech.relaycorp.relaynet.ramf

import java.io.InputStream

interface RAMFMessageCompanion<Message : RAMFMessage> {
    fun deserialize(serialization: ByteArray): Message
    fun deserialize(serialization: InputStream): Message
}
