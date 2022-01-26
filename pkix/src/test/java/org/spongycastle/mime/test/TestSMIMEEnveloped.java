package org.spongycastle.mime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.spongycastle.cms.CMSAlgorithm;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.OriginatorInformation;
import org.spongycastle.cms.RecipientInformation;
import org.spongycastle.cms.RecipientInformationStore;
import org.spongycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.spongycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientId;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.spongycastle.cms.test.CMSTestUtil;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.mime.Headers;
import org.spongycastle.mime.MimeParser;
import org.spongycastle.mime.MimeParserContext;
import org.spongycastle.mime.MimeParserProvider;
import org.spongycastle.mime.smime.SMIMEEnvelopedWriter;
import org.spongycastle.mime.smime.SMimeParserListener;
import org.spongycastle.mime.smime.SMimeParserProvider;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.io.Streams;

public class TestSMIMEEnveloped
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String          _signDN;
    private static KeyPair          _signKP;

    private static String          _reciDN;
    private static KeyPair          _reciKP;

    private static X509Certificate _reciCert;

    private static boolean         _initialised = false;

    private static final byte[] testMessage = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
        "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
        "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
        "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
        "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
        "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
        "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
        "wMTMyLS0NCg==");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            _initialised = true;

            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }
    
    public void testSMIMEEnveloped()
        throws Exception
    {
        InputStream inputStream = this.getClass().getResourceAsStream("test256.message");

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(new ReadOnceInputStream(Streams.readAll(inputStream)));

        final TestDoneFlag dataParsed = new TestDoneFlag();

        p.parse(new SMimeParserListener()
        {
            public void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
                throws IOException, CMSException
            {
                RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

                assertNotNull(recipInfo);

                byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));
                assertTrue(org.spongycastle.util.Arrays.areEqual(testMessage, content));

                dataParsed.markDone();
            }
        });

        assertTrue(dataParsed.isDone());
    }

    public void testKeyTransAES128()
        throws Exception
    {
        //
        // output
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMEEnvelopedWriter.Builder envBldr = new SMIMEEnvelopedWriter.Builder();

        envBldr.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        SMIMEEnvelopedWriter envWrt = envBldr.build(bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        OutputStream out = envWrt.getContentStream();

        out.write(testMessage);

        out.close();
        
        //
        // parse
        //
        final TestDoneFlag dataParsed = new TestDoneFlag();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(new ReadOnceInputStream(bOut.toByteArray()));

        p.parse(new SMimeParserListener()
        {
            public void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
                throws IOException, CMSException
            {
                RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(_reciCert));

                assertNotNull(recipInfo);

                byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()));
                assertTrue(org.spongycastle.util.Arrays.areEqual(testMessage, content));

                dataParsed.markDone();
            }
        });

        assertTrue(dataParsed.isDone());
    }

    private X509Certificate loadCert(String name)
        throws IOException
    {
        try
        {
            return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(getClass().getResourceAsStream(name));
        }
        catch (Exception e)
        {
            throw new IOException(e.getMessage());
        }
    }

    private PrivateKey loadKey(String name)
        throws IOException
    {
        return new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair)(new PEMParser(new InputStreamReader(getClass().getResourceAsStream(name)))).readObject()).getPrivate();
    }
}
