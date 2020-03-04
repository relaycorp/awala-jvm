package tech.relaycorp.relaynet.ramf

import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import java.io.File
import java.time.LocalDateTime
import kotlin.test.Test

class RAMFSerializerTest {
    @Test
    fun testSerializer() {
        val ramf = RAMFSerializer(
                "04334", "message-id", LocalDateTime.now(), 1, "payload".toByteArray()
        )

        val out = ramf.encode()

        File("/home/gus/tmp/ramf.der").writeBytes(out)
    }
}
