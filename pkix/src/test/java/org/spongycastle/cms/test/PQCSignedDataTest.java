package org.spongycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.bc.BCObjectIdentifiers;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.cms.CMSAttributes;
import org.spongycastle.asn1.cms.ContentInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSTypedData;
import org.spongycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.SignerId;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationStore;
import org.spongycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.spongycastle.util.Store;

public class PQCSignedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String BCPQC = BouncyCastlePQCProvider.PROVIDER_NAME;

    boolean DEBUG = true;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _signDN;
    private static KeyPair         _signKP;
    private static X509Certificate _signCert;

    private static boolean _initialised = false;


                                                     List crlList = new ArrayList();
    private static final Set noParams = new HashSet();

    static
    {
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);
    }

    public PQCSignedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
        throws Exception
    {
        init();

        junit.textui.TestRunner.run(PQCSignedDataTest.class);
    }

    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(PQCSignedDataTest.class));
    }

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

            if (Security.getProvider(BC) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }
            if (Security.getProvider(BCPQC) == null)
            {
                Security.addProvider(new BouncyCastlePQCProvider());
            }

            _origDN   = "O=Bouncy Castle, C=AU";
            _origKP   = PQCTestUtil.makeKeyPair();
            _origCert = PQCTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _signKP   = PQCTestUtil.makeKeyPair();
            _signCert = PQCTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);
        }
    }

    private void verifyRSASignatures(CMSSignedData s, byte[] contentDigest)
        throws Exception
    {
        Store                   certStore = s.getCertificates();
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(cert)));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }

    private void verifySignatures(CMSSignedData s, byte[] contentDigest) 
        throws Exception
    {
        Store                   certStore = s.getCertificates();
        Store                   crlStore = s.getCRLs();
        SignerInformationStore  signers = s.getSignerInfos();
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
            
            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getMatches(null);
        Collection crlColl = crlStore.getMatches(null);

        assertEquals(certColl.size(), s.getCertificates().getMatches(null).size());
        assertEquals(crlColl.size(), s.getCRLs().getMatches(null).size());
    }

    public void testSPHINCS256Encapsulated()
        throws Exception
    {
        List              certList = new ArrayList();
        CMSTypedData      msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider(BCPQC).build(_origKP.getPrivate()), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream      aIn = new ASN1InputStream(bIn);
        
        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
        SignerId                sid = null;

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC);

            sid = signer.getSID();
            
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }
}
