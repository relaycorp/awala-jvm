package tech.relaycorp.relaynet.messages

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.ramf.RAMFException
import tech.relaycorp.relaynet.utils.RAMFUtils
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

class RecipientTest {
    @Nested
    inner class Serialize {
        @Nested
        inner class Id {
            @Test
            fun `Id should be first item in sub-sequence`() {
                val recipient = Recipient(RAMFUtils.recipientId)

                val serialization = recipient.serialize()

                val idEncoded = ASN1TaggedObject.getInstance(serialization.first())
                val idString =
                    ASN1Utils.getVisibleString(idEncoded)
                assertEquals(recipient.id, idString.string)
            }

            @Test
            fun `Id should be implicitly tagged`() {
                val recipient = Recipient(RAMFUtils.recipientId)

                val serialization = recipient.serialize()

                val idEncoded = serialization.first() as ASN1TaggedObject
                assertFalse(idEncoded.isExplicit)
            }
        }

        @Nested
        inner class InternetAddress {
            @Test
            fun `Internet address should be absent if unspecified`() {
                val recipient = Recipient(RAMFUtils.recipientId)

                val serialization = recipient.serialize()

                assertEquals(1, serialization.size())
            }

            @Test
            fun `Internet address should be second item in sub-sequence`() {
                val recipient = Recipient(RAMFUtils.recipientId, RAMFUtils.recipientInternetAddress)

                val serialization = recipient.serialize()

                assertEquals(2, serialization.size())
                val internetAddressEncoded = serialization.objects.toList()[1] as ASN1TaggedObject
                val internetAddressString = ASN1Utils.getVisibleString(internetAddressEncoded)
                assertEquals(recipient.internetAddress, internetAddressString.string)
            }

            @Test
            fun `Internet address should be implicitly tagged`() {
                val recipient = Recipient(RAMFUtils.recipientId, RAMFUtils.recipientInternetAddress)

                val serialization = recipient.serialize()

                val internetAddressEncoded = serialization.objects.toList()[1] as ASN1TaggedObject
                assertFalse(internetAddressEncoded.isExplicit)
            }
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be a SEQUENCE`() {
            val exception = assertThrows<RAMFException> {
                Recipient.deserialize(DERNull.INSTANCE)
            }

            assertEquals("Recipient is not a SEQUENCE", exception.message)
            assertTrue(exception.cause is IllegalArgumentException)
        }

        @Test
        fun `SEQUENCE should have at least one item`() {
            val exception = assertThrows<RAMFException> {
                Recipient.deserialize(DERSequence())
            }

            assertEquals("Recipient SEQUENCE is empty", exception.message)
        }

        @Nested
        inner class Id {
            @Test
            fun `Id should be extracted`() {
                val recipient = Recipient(RAMFUtils.recipientId)

                val recipientDeserialized = Recipient.deserialize(recipient.serialize())

                assertEquals(recipient.id, recipientDeserialized.id)
            }

            @Test
            fun `Id of up to 1024 octets should be accepted`() {
                val recipient = Recipient("0${"a".repeat(1023)}")

                val recipientDeserialized = Recipient.deserialize(recipient.serialize())

                assertEquals(recipient.id, recipientDeserialized.id)
            }

            @Test
            fun `Id spanning more than 1024 octets should be refused`() {
                val recipient = Recipient("0${"a".repeat(1024)}")
                val serialization = recipient.serialize()

                val exception = assertThrows<RAMFException> {
                    Recipient.deserialize(serialization)
                }

                assertEquals(
                    "Recipient id should not span more than 1024 characters (got 1025)",
                    exception.message
                )
            }

            @Test
            fun `Malformed id should be refused`() {
                val recipient = Recipient("not an id")
                val serialization = recipient.serialize()

                val exception = assertThrows<RAMFException> {
                    Recipient.deserialize(serialization)
                }

                assertEquals(
                    "Recipient id is malformed (${recipient.id})",
                    exception.message
                )
            }
        }

        @Nested
        inner class InternetAddress {
            @Test
            fun `Address should be null if absent`() {
                val serialization = ASN1Utils.makeSequence(
                    listOf(DERVisibleString(RAMFUtils.recipientId)),
                    false,
                )

                val recipientDeserialized = Recipient.deserialize(serialization)

                assertNull(recipientDeserialized.internetAddress)
            }

            @Test
            fun `Domain name should be accepted`() {
                val recipient = Recipient(RAMFUtils.recipientId, RAMFUtils.recipientInternetAddress)

                val recipientDeserialized = Recipient.deserialize(recipient.serialize())

                assertEquals(
                    RAMFUtils.recipientInternetAddress,
                    recipientDeserialized.internetAddress
                )
            }

            @Test
            fun `Address spanning more than 1024 octets should be refused`() {
                val longDomain = "${"a".repeat(1021)}.com"
                val recipient = Recipient(RAMFUtils.recipientId, longDomain)
                val serialization = recipient.serialize()

                val exception = assertThrows<RAMFException> { Recipient.deserialize(serialization) }

                assertEquals(
                    "Internet address should not span more than 1024 characters (got 1025)",
                    exception.message
                )
            }

            @Test
            fun `Malformed domain name should be refused`() {
                val malformedDomain = "not really a domain name"
                val recipient = Recipient(RAMFUtils.recipientId, malformedDomain)
                val serialization = recipient.serialize()

                val exception = assertThrows<RAMFException> { Recipient.deserialize(serialization) }

                assertEquals(
                    "Internet address is malformed ($malformedDomain)",
                    exception.message
                )
            }
        }
    }
}
