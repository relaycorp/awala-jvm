package tech.relaycorp.relaynet.ramf

interface RAMFMessageCompanion<Message : RAMFMessage> {
    fun deserialize(serialization: ByteArray): Message
}
