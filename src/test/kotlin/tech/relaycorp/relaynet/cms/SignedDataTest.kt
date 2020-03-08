package tech.relaycorp.relaynet.cms

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class Sign {
    @Test
    @Disabled
    fun `Serialization should be DER-encoded`() {
    }

    @Test
    @Disabled
    fun `SignedData value should be wrapped in ContentInfo`() {
    }

    @Test
    @Disabled
    fun `SignedData version should be set to 1`() {
    }

    @Nested
    inner class SignerInfo {
        @Test
        @Disabled
        fun `There should only be one SignerInfo`() {
        }

        @Test
        @Disabled
        fun `Version should be set to 1`() {
        }

        @Test
        @Disabled
        fun `SignerIdentifier should be IssuerAndSerialNumber`() {
        }

        @Test
        @Disabled
        fun `Content should be attached`() {
        }
    }

    @Nested
    inner class SignedAttributes {
        @Test
        @Disabled
        fun `Signed attributes should be present`() {
        }

        @Test
        @Disabled
        fun `Content type attribute should be set to CMS Data`() {
        }

        @Test
        @Disabled
        fun `Plaintext digest should be present`() {
        }
    }

    @Nested
    inner class AttachedCertificates {
        @Test
        @Disabled
        fun `Signer certificate should be attached`() {
        }

        @Test
        @Disabled
        fun `CA certificate chain should optionally be attached`() {
        }
    }

    @Nested
    inner class HashingAlgorithms {
        @Test
        @Disabled
        fun `SHA-256 should be used by default`() {
        }

        @Test
        @Disabled
        fun `SHA-384 should be supported`() {
        }

        @Test
        @Disabled
        fun `SHA-512 should be supported`() {
        }

        @Test
        @Disabled
        fun `SHA-1 should not be supported`() {
        }

        @Test
        @Disabled
        fun `MD5 should not be supported`() {
        }
    }
}

class VerifySignatureTest {
    @Test
    @Disabled
    fun `Invalid DER values should be refused`() {}

    @Test
    @Disabled
    fun `Well formed but invalid signatures should be rejected`() {}

    @Test
    @Disabled
    fun `Valid signatures should be accepted`() {}

    @Test
    @Disabled
    fun `Signer certificate should be output when verification passes`() {}

    @Test
    @Disabled
    fun `Attached CA certificates should be output when verification passes`() {}
}
