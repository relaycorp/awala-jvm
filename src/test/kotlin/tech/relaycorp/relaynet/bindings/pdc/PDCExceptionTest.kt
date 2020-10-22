package tech.relaycorp.relaynet.bindings.pdc

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals

/**
 * Pointless tests for exceptions just to maintain 100% code coverage. These exceptions aren't
 * executed because they're only exposed in an interface.
 */
class PDCExceptionTest {
    @ParameterizedTest
    @ValueSource(
        classes = [
            ServerConnectionException::class,
            ServerBindingException::class,
            ClientBindingException::class,
            RejectedParcelException::class,
            NonceSignerException::class
        ]
    )
    fun message(clazz: Class<PDCException>) {
        val exceptionMessage = "message"
        val exception = try {
            clazz.getConstructor(String::class.java).newInstance(exceptionMessage)
        } catch (_: NoSuchMethodException) {
            clazz.getConstructor(String::class.java, Throwable::class.java)
                .newInstance(exceptionMessage, null)
        }

        assertEquals(exceptionMessage, exception.message)
    }

    @Test
    fun optionalCauses() {
        ServerConnectionException("")
        ServerBindingException("")
    }
}
