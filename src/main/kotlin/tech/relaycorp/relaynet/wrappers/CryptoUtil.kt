package tech.relaycorp.relaynet.wrappers

import java.security.SecureRandom

class CryptoUtil {
    companion object {
        fun generateRandom64BitValue(): Long {
            val random = SecureRandom()
            return random.nextLong()
        }
    }
}
