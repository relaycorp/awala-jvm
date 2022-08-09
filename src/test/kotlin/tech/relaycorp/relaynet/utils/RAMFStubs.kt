package tech.relaycorp.relaynet.utils

import tech.relaycorp.relaynet.messages.Recipient

object RAMFStubs {
    val recipientId = PDACertPath.PRIVATE_ENDPOINT.subjectId
    val recipient = Recipient(recipientId)
    const val recipientInternetAddress = "braavos.relaycorp.cloud"
}
