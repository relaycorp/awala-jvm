package tech.relaycorp.relaynet.wrappers.cms

import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.KeyTransRecipientInformation
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient
import org.junit.jupiter.api.Test
import tech.relaycorp.relaynet.cms.EnvelopedData
import tech.relaycorp.relaynet.issueStubCertificate
import tech.relaycorp.relaynet.wrappers.generateRSAKeyPair
import kotlin.test.assertEquals

class EnvelopedDataTest {
    @Test
    fun testPOC() {
        val plaintext = "hello".toByteArray()
        val keyPair = generateRSAKeyPair()
        val cert = issueStubCertificate(keyPair.public, keyPair.private)
        val serialization = EnvelopedData.encrypt(plaintext, cert).bcEnvelopedData.encoded

        val bcEnvelopedData = CMSEnvelopedData(serialization)

        val recipients = bcEnvelopedData.recipientInfos.recipients
        val recipientInfo = recipients.iterator().next() as KeyTransRecipientInformation
        val recipient: JceKeyTransRecipient = JceKeyTransEnvelopedRecipient(keyPair.private)

        assertEquals(plaintext.asList(), recipientInfo.getContent(recipient).asList())
    }
}
