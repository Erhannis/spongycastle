package org.spongycastle.cms.test;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.crypto.spec.OAEPParameterSpec;

import junit.framework.TestCase;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.cms.CMSAlgorithm;
import org.spongycastle.cms.CMSEnvelopedData;
import org.spongycastle.cms.CMSEnvelopedDataGenerator;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.RecipientId;
import org.spongycastle.cms.RecipientInformation;
import org.spongycastle.cms.RecipientInformationStore;
import org.spongycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.spongycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientId;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.spongycastle.jcajce.util.AnnotatedPrivateKey;
import org.spongycastle.jcajce.util.PrivateKeyAnnotator;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.jcajce.JcaAlgorithmParametersConverter;

public class AnnotatedKeyTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static String _reciDN2;
    private static KeyPair _reciKP;
    private static KeyPair _reciOaepKP;
    private static X509Certificate _reciCert;
    private static X509Certificate _reciCertOaep;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;
    private static KeyPair _reciEcKP2;
    private static X509Certificate _reciEcCert2;
    private static KeyPair _reciKemsKP;
    private static X509Certificate _reciKemsCert;

    private static KeyPair _origDhKP;
    private static KeyPair _reciDhKP;
    private static X509Certificate _reciDhCert;

    private static boolean _initialised = false;

    public void setUp()
        throws Exception
    {
        init();
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            _reciCertOaep = CMSTestUtil.makeOaepCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
            _reciEcKP2 = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert2 = CMSTestUtil.makeCertificate(_reciEcKP2, _reciDN2, _signKP, _signDN);

            _origDhKP = CMSTestUtil.makeDhKeyPair();
            _reciDhKP = CMSTestUtil.makeDhKeyPair();
            _reciDhCert = CMSTestUtil.makeCertificate(_reciDhKP, _reciDN, _signKP, _signDN);

            _reciKemsKP = CMSTestUtil.makeKeyPair();
            _reciKemsCert = CMSTestUtil.makeCertificate(_reciKemsKP, _reciDN, _signKP, _signDN, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_rsa_KEM));
        }
    }

    public void testKeyTransOAEPDefault()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert, paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, recipient.getKeyEncryptionAlgorithm().getAlgorithm());

            AnnotatedPrivateKey privateKey = PrivateKeyAnnotator.annotate(_reciKP.getPrivate(), "fred");

            assertEquals("fred", privateKey.getAnnotation(AnnotatedPrivateKey.LABEL));
            assertEquals("fred", privateKey.toString());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCert);

        Collection<RecipientInformation> collection = recipients.getRecipients(id);
        if (collection.size() != 2)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }
}
