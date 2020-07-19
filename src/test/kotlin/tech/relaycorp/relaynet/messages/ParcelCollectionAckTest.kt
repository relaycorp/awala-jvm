package tech.relaycorp.relaynet.messages

import org.bouncycastle.asn1.DERVisibleString
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import tech.relaycorp.relaynet.wrappers.asn1.ASN1Utils
import kotlin.test.Test
import kotlin.test.assertEquals

internal class ParcelCollectionAckTest {
    private val senderEndpointPrivateAddress = "0deadbeef"
    private val recipientEndpointAddress = "https://ping.relaycorp.tech"
    private val parcelId = "the-parcel-id"

    @Nested
    inner class Serialize {
        @Test
        fun `Serialization should start with format signature`() {
            val pca = ParcelCollectionAck(
                senderEndpointPrivateAddress,
                recipientEndpointAddress,
                parcelId
            )

            val serialization = pca.serialize()

            assertEquals(
                byteArrayOf(*"Relaynet".toByteArray(), 0x51, 0).asList(),
                serialization.slice(0..9)
            )
        }

        @Test
        fun `ACK should be serialized as a 3-item sequence`() {
            val pca = ParcelCollectionAck(
                senderEndpointPrivateAddress,
                recipientEndpointAddress,
                parcelId
            )

            val serialization = pca.serialize()

            val derSequence = serialization.slice(10 until serialization.size)
            val sequenceItems = ASN1Utils.deserializeSequence(derSequence.toByteArray())
            assertEquals(3, sequenceItems.size)
            assertEquals(
                senderEndpointPrivateAddress,
                DERVisibleString.getInstance(sequenceItems[0]).string
            )
            assertEquals(
                recipientEndpointAddress,
                DERVisibleString.getInstance(sequenceItems[1]).string
            )
            assertEquals(parcelId, DERVisibleString.getInstance(sequenceItems[2]).string)
        }
    }

    @Nested
    inner class Deserialize {
        @Test
        @Disabled
        fun `Serialization should start with format signature`() {
        }

        @Test
        @Disabled
        fun `ACK should be refused if it has fewer than 3 items`() {
        }

        @Test
        @Disabled
        fun `Sender endpoint private address should be a VisibleString`() {
        }

        @Test
        @Disabled
        fun `Recipient endpoint address should be a VisibleString`() {
        }

        @Test
        @Disabled
        fun `Parcel id should be a VisibleString`() {
        }
    }
}
