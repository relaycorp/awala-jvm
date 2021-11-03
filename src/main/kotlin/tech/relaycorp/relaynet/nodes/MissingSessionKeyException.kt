package tech.relaycorp.relaynet.nodes

import tech.relaycorp.relaynet.RelaynetException

class MissingSessionKeyException(message: String) : RelaynetException(message, null)
