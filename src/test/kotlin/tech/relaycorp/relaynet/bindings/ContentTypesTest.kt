package tech.relaycorp.relaynet.bindings

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

// Because the enum is only used externally, we're writing this test just to exercise the code
// and get it test-covered.
class ContentTypesTest {
    @Test
    fun `Value should be output`() {
        assertEquals("application/vnd.relaynet.parcel", ContentTypes.PARCEL.value)
    }
}
