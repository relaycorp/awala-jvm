package tech.relaycorp.relaynet

import com.beanit.jasn1.ber.types.string.BerVisibleString
import kotlin.test.Test
import kotlin.test.assertEquals


class RAMFTest {
    @Test
    fun testSerializer() {
        val ramf = RAMF()
        ramf.recipient = BerVisibleString("04334")
        assertEquals(BerVisibleString("04334").toString(), ramf.recipient!!.toString())
    }
}