package tech.relaycorp.relaynet.wrappers

import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class DNSTest {
    @Nested
    inner class IsValidDomainName {
        @Test
        fun `Syntactically invalid domain names should be invalid`() {
            assertFalse(DNS.isValidDomainName("relaycorp dot tech"))
            assertFalse(DNS.isValidDomainName("someone@relaycorp.tech"))
            assertFalse(DNS.isValidDomainName("https://relaycorp.tech"))
        }

        @Test
        fun `TLDs should be invalid`() {
            assertFalse(DNS.isValidDomainName("tech"))
        }

        @Test
        fun `Domain names with leading dot should be invalid`() {
            assertFalse(DNS.isValidDomainName(".relaycorp.tech"))
        }

        @Test
        fun `Domain names with trailing dot should be invalid`() {
            assertFalse(DNS.isValidDomainName("relaycorp.tech."))
        }

        @Test
        fun `Second-level domains should be valid`() {
            assertTrue(DNS.isValidDomainName("relaycorp.tech"))
        }

        @Test
        fun `Third-level domains should be valid`() {
            assertTrue(DNS.isValidDomainName("foo.relaycorp.tech"))
        }

        @Test
        fun `Long TLDs should be supported`() {
            assertTrue(DNS.isValidDomainName("example.thisisalongtld"))
        }

        @Test
        fun `Punycode TLDs should be supported`() {
            assertTrue(DNS.isValidDomainName("example.XN--11B4C3D"))
            assertTrue(DNS.isValidDomainName("example.XN--VERMGENSBERATUNG-PWB"))
        }
    }
}
