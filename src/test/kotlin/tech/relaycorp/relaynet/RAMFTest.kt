package tech.relaycorp.relaynet

import com.beanit.jasn1.ber.ReverseByteArrayOutputStream
import com.beanit.jasn1.ber.types.BerDateTime
import com.beanit.jasn1.ber.types.BerInteger
import com.beanit.jasn1.ber.types.BerOctetString
import com.beanit.jasn1.ber.types.string.BerVisibleString
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class RAMFTest {
    @Test
    fun testSerializer() {
        val ramf = RAMF()
        ramf.recipient = BerVisibleString("04334")
        ramf.messageId = BerVisibleString("message-id")
        ramf.creationTimeUtc = BerDateTime("20191201183001")
        ramf.ttl = BerInteger(1L)
        ramf.payload = BerOctetString("payload".toByteArray())

        val out = ReverseByteArrayOutputStream(1000)
        ramf.encode(out)

        File("/home/gus/tmp/ramf.der").writeBytes(out.array)
        assertEquals(BerVisibleString("04334").toString(), ramf.recipient!!.toString())
    }
}
