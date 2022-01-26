package org.spongycastle.tsp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.spongycastle.tsp.TSPAlgorithms;
import org.spongycastle.tsp.TimeStampRequest;
import org.spongycastle.tsp.TimeStampRequestGenerator;
import org.spongycastle.tsp.TimeStampResponse;
import org.spongycastle.tsp.TimeStampResponseGenerator;
import org.spongycastle.tsp.TimeStampToken;
import org.spongycastle.tsp.TimeStampTokenGenerator;

public class PQCTSPTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testLMS()
        throws Exception
    {
        BouncyCastlePQCProvider pqcProvider = new BouncyCastlePQCProvider();
        Security.addProvider(pqcProvider);

        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("LMS", "BCPQC");

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            fail("error setting up keys - " + e.toString());
            return;
        }

        //
        // extensions
        //

        //
        // create the certificate - version 1
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("LMS")
            .setProvider(pqcProvider).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name("CN=Test"),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            new X500Name("CN=Test"),
            pubKey);

        certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(certGen.build(sigGen));

        ContentSigner signer = new JcaContentSignerBuilder("LMS").setProvider(pqcProvider).build(privKey);

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                .setContentDigest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
                .build(signer, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        // tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SM3, new byte[32], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build())
            .setProvider(pqcProvider).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }
}
