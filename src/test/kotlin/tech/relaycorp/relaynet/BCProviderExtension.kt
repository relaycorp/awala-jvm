package tech.relaycorp.relaynet

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.extension.BeforeAllCallback
import org.junit.jupiter.api.extension.ExtensionContext
import java.security.Security

class BCProviderExtension : BeforeAllCallback {
    companion object {
        var wasBcProviderAdded = false
    }
    override fun beforeAll(_context: ExtensionContext?) {
        if (!wasBcProviderAdded) {
            Security.addProvider(BouncyCastleProvider())
            wasBcProviderAdded = true
        }
    }
}
