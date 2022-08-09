package tech.relaycorp.relaynet.messages

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import tech.relaycorp.relaynet.utils.RAMFStubs
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Exception
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils

internal class ParcelCollectionAckTest {
    private val senderEndpointId = "0deadbeef"
    private val recipientEndpointId = RAMFStubs.recipientInternetAddress
    private val parcelId = "the-parcel-id"

    private val formatSignature = byteArrayOf(*"Awala".toByteArray(), 0x51, 0)

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should start with format signature`() {
            val pca = ParcelCollectionAck(
                senderEndpointId,
                recipientEndpointId,
                parcelId
            )

            val serialization = pca.serialize()

            assertEquals(
                formatSignature.asList(),
                serialization.slice(formatSignature.indices)
            )
        }

        @Test
        fun `ACK should be serialized as a 3-item sequence`() {
            val pca = ParcelCollectionAck(
                senderEndpointId,
                recipientEndpointId,
                parcelId
            )

            val serialization = pca.serialize()

            val derSequence = serialization.slice(7 until serialization.size)
            val sequenceItems =
                ASN1Utils.deserializeHeterogeneousSequence(derSequence.toByteArray())
            assertEquals(3, sequenceItems.size)
            assertEquals(
                senderEndpointId,
                ASN1Utils.getVisibleString(sequenceItems[0]).string
            )
            assertEquals(
                recipientEndpointId,
                ASN1Utils.getVisibleString(sequenceItems[1]).string
            )
            assertEquals(
                parcelId,
                ASN1Utils.getVisibleString(sequenceItems[2]).string
            )
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        fun `Serialization should be long enough to potentially contain format signature`() {
            val exception = assertThrows<InvalidMessageException> {
                ParcelCollectionAck.deserialize("AwalaP".toByteArray())
            }

            assertEquals("Message is too short to contain format signature", exception.message)
        }

        @Test
        fun `Serialization should start with format signature`() {
            val exception = assertThrows<InvalidMessageException> {
                ParcelCollectionAck.deserialize("AwalaP0".toByteArray())
            }

            assertEquals("Format signature is not that of a PCA", exception.message)
        }

        @Test
        fun `Serialization should contain valid DER sequence`() {
            val serialization = formatSignature + byteArrayOf(1)

            val exception = assertThrows<InvalidMessageException> {
                ParcelCollectionAck.deserialize(serialization)
            }

            assertEquals("PCA is not a valid DER sequence", exception.message)
            assertTrue(exception.cause is ASN1Exception)
        }

        @Test
        fun `ACK should be refused if it has fewer than 3 items`() {
            val serialization = formatSignature + ASN1Utils.serializeSequence(
                listOf(
                    DERVisibleString("one"),
                    DERVisibleString("two")
                ),
                false
            )

            val exception = assertThrows<InvalidMessageException> {
                ParcelCollectionAck.deserialize(serialization)
            }

            assertEquals("PCA should have 3 items (got 2)", exception.message)
        }

        @Test
        fun `Sender endpoint id should be decoded as a VisibleString`() {
            val serialization = ParcelCollectionAck(
                senderEndpointId,
                recipientEndpointId,
                parcelId
            ).serialize()

            val pca = ParcelCollectionAck.deserialize(serialization)

            assertEquals(pca.senderEndpointId, senderEndpointId)
        }

        @Test
        fun `Recipient endpoint address should be decoded as a VisibleString`() {
            val serialization = ParcelCollectionAck(
                senderEndpointId,
                recipientEndpointId,
                parcelId
            ).serialize()

            val pca = ParcelCollectionAck.deserialize(serialization)

            assertEquals(pca.recipientEndpointId, recipientEndpointId)
        }

        @Test
        fun `Parcel id should be decoded as a VisibleString`() {
            val serialization = ParcelCollectionAck(
                senderEndpointId,
                recipientEndpointId,
                parcelId
            ).serialize()

            val pca = ParcelCollectionAck.deserialize(serialization)

            assertEquals(pca.parcelId, parcelId)
        }
    }
}
