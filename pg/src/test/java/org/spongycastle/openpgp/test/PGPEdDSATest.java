package org.spongycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.spongycastle.crypto.generators.X25519KeyPairGenerator;
import org.spongycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.spongycastle.crypto.params.X25519KeyGenerationParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPLiteralDataGenerator;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.bc.BcPGPObjectFactory;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.UncloseableOutputStream;

public class PGPEdDSATest
    extends SimpleTest
{
    private static final String edDSASampleKey =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Alice's OpenPGP certificate\n" +
            "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
            "\n" +
            "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
            "b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE\n" +
            "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy\n" +
            "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO\n" +
            "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4\n" +
            "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s\n" +
            "E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb\n" +
            "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn\n" +
            "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=\n" +
            "=iIGO\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String edDSASecretKey =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Alice's OpenPGP Transferable Secret Key\n" +
            "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
            "\n" +
            "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
            "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
            "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
            "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
            "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
            "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
            "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
            "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
            "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
            "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
            "Pnn+We1aTBhaGa86AQ==\n" +
            "=n8OM\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String revBlock =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Alice's revocation certificate\n" +
            "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
            "\n" +
            "iHgEIBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXaWkOwIdAAAKCRDyMVUM\n" +
            "T0fjjoBlAQDA9ukZFKRFGCooVcVoDVmxTaHLUXlIg9TPh2f7zzI9KgD/SLNXUOaH\n" +
            "O6TozOS7C9lwIHwwdHdAxgf5BzuhLT9iuAM=\n" +
            "=Tm8h\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    public String getName()
    {
        return "PGPEdDSATest";
    }

    private void encryptDecryptTest(PGPPublicKey pubKey, PGPPrivateKey secKey)
        throws Exception
    {
        byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setProvider("BC").setSecureRandom(new SecureRandom()));

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secKey));

        pgpF = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void encryptDecryptBcTest(PGPPublicKey pubKey, PGPPrivateKey secKey)
        throws Exception
    {
        byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setSecureRandom(new SecureRandom()));

        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubKey));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(secKey));

        pgpF = new BcPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void keyringTest()
        throws Exception
    {
        String identity = "eric.spongycastle.org";
        char[] passPhrase = "Hello, world!".toCharArray();

        KeyPairGenerator edKp = KeyPairGenerator.getInstance("EdDSA", "BC");

        edKp.initialize(new ECNamedCurveGenParameterSpec("Ed25519"));

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.EDDSA, edKp.generateKeyPair(), new Date());

        KeyPairGenerator dhKp = KeyPairGenerator.getInstance("XDH", "BC");

        dhKp.initialize(new ECNamedCurveGenParameterSpec("X25519"));

        PGPKeyPair dhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, dhKp.generateKeyPair(), new Date());

        encryptDecryptTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());
        encryptDecryptBcTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            identity, sha1Calc, null, null,
            new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(dhKeyPair);

        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        secRing.encode(secretOut);

        secretOut.close();
        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new JcaKeyFingerprintCalculator());

        Iterator pIt = secRing.getPublicKeys();
        pIt.next();
        
        PGPPublicKey sKey = (PGPPublicKey)pIt.next();
        PGPPublicKey vKey = secRing.getPublicKey();

        Iterator    sIt = sKey.getSignatures();
        int count = 0;
        while (sIt.hasNext())
        {
            PGPSignature    sig = (PGPSignature)sIt.next();

            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                count++;
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), vKey);

                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }

        isTrue(count == 1);

        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new JcaKeyFingerprintCalculator());
        PGPPublicKey pubKey = null;
        PGPPrivateKey privKey = null;

        for (Iterator it = secRing.getPublicKeys(); it.hasNext();)
        {
            pubKey = (PGPPublicKey)it.next();
            if (pubKey.isEncryptionKey())
            {
                privKey = secRing.getSecretKey(pubKey.getKeyID()).extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().build(passPhrase));
                break;
            }
        }

        encryptDecryptTest(pubKey, privKey);
        encryptDecryptBcTest(pubKey, privKey);
    }

    private void keyringBcTest()
        throws Exception
    {
        String identity = "eric.spongycastle.org";
        char[] passPhrase = "Hello, world!".toCharArray();

        Ed25519KeyPairGenerator edKp = new Ed25519KeyPairGenerator();
        edKp.init(new Ed25519KeyGenerationParameters(null));

        PGPKeyPair dsaKeyPair = new BcPGPKeyPair(PGPPublicKey.EDDSA, edKp.generateKeyPair(), new Date());

        X25519KeyPairGenerator dhKp = new X25519KeyPairGenerator();
        dhKp.init(new X25519KeyGenerationParameters(null));

        PGPKeyPair dhKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDH, dhKp.generateKeyPair(), new Date());

        encryptDecryptBcTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());
        encryptDecryptTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());

        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            identity, sha1Calc, null, null,
            new BcPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).build(passPhrase));

        keyRingGen.addSubKey(dhKeyPair);

        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        secRing.encode(secretOut);

        secretOut.close();
        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new BcKeyFingerprintCalculator());

        Iterator pIt = secRing.getPublicKeys();
        pIt.next();
        
        PGPPublicKey sKey = (PGPPublicKey)pIt.next();
        PGPPublicKey vKey = secRing.getPublicKey();

        Iterator    sIt = sKey.getSignatures();
        int count = 0;
        while (sIt.hasNext())
        {
            PGPSignature    sig = (PGPSignature)sIt.next();

            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                count++;
                sig.init(new BcPGPContentVerifierBuilderProvider(), vKey);

                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }

        isTrue(count == 1);

        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new BcKeyFingerprintCalculator());
        PGPPublicKey pubKey = null;
        PGPPrivateKey privKey = null;

        for (Iterator it = secRing.getPublicKeys(); it.hasNext();)
        {
            pubKey = (PGPPublicKey)it.next();
            if (pubKey.isEncryptionKey())
            {
                privKey = secRing.getSecretKey(pubKey.getKeyID()).extractPrivateKey(
                    new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));
                break;
            }
        }

        encryptDecryptBcTest(pubKey, privKey);
        encryptDecryptTest(pubKey, privKey);
    }

    public void performTest()
        throws Exception
    {
        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(edDSASampleKey)));

        PGPPublicKeyRing pubKeyRing = new PGPPublicKeyRing(aIn, new JcaKeyFingerprintCalculator());

        isTrue(areEqual(Hex.decode("EB85 BB5F A33A 75E1 5E94 4E63 F231 550C 4F47 E38E"), pubKeyRing.getPublicKey().getFingerprint()));

        aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(edDSASecretKey)));

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(aIn, new JcaKeyFingerprintCalculator());

        isTrue(secRing.getSecretKey().isSigningKey());

        PGPSignatureGenerator pgpGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.EDDSA, HashAlgorithmTags.SHA256));

        pgpGen.init(PGPSignature.SUBKEY_BINDING, secRing.getSecretKey().extractPrivateKey(null));

        PGPSignature sig = pgpGen.generateCertification(pubKeyRing.getPublicKey(), pubKeyRing.getPublicKey(5145070902336167606L));

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKeyRing.getPublicKey());

        isTrue(sig.verifyCertification(pubKeyRing.getPublicKey(), pubKeyRing.getPublicKey(5145070902336167606L)));

        encryptDecryptTest(pubKeyRing.getPublicKey(5145070902336167606L),
            secRing.getSecretKey(5145070902336167606L).extractPrivateKey(null));

        encryptDecryptBcTest(pubKeyRing.getPublicKey(5145070902336167606L),
            secRing.getSecretKey(5145070902336167606L).extractPrivateKey(null));

        aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(revBlock)));

        PGPSignatureList sigs = (PGPSignatureList)new PGPObjectFactory(aIn, new JcaKeyFingerprintCalculator()).nextObject();

        sig = sigs.get(0);

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKeyRing.getPublicKey());

        isTrue(sig.verifyCertification(pubKeyRing.getPublicKey()));

        keyringTest();
        keyringBcTest();
        sksKeyTest();
        aliceBcKeyTest();
    }

    private void aliceBcKeyTest()
        throws Exception
    {
        byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};
        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(edDSASampleKey)));

        PGPPublicKeyRing rng = new PGPPublicKeyRing(aIn, new JcaKeyFingerprintCalculator());

        aIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(edDSASecretKey)));

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(aIn, new JcaKeyFingerprintCalculator());

        PGPPublicKey pubKey = rng.getPublicKey(5145070902336167606L);
        PGPPrivateKey privKey = secRing.getSecretKey(5145070902336167606L).extractPrivateKey(null);
        
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        BcPGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128);
        encBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encBuilder);

        BcPublicKeyKeyEncryptionMethodGenerator
            encMethodGen = new BcPublicKeyKeyEncryptionMethodGenerator(pubKey);
        cPk.addMethod(encMethodGen);

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(privKey));

        pgpF = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void sksKeyTest()
        throws Exception
    {
        byte[] data = Strings.toByteArray("testing, 1, 2, 3, testing...");

        ArmoredInputStream aIn = new ArmoredInputStream(this.getClass().getResourceAsStream("eddsa-sks-pub-keyring.asc"));

        // make sure we can parse it without falling over.
        PGPPublicKeyRing rng = new PGPPublicKeyRing(aIn, new JcaKeyFingerprintCalculator());

        BcPGPDataEncryptorBuilder encBuilder = new
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128);
        encBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encDataGen = new
            PGPEncryptedDataGenerator(encBuilder);

        BcPublicKeyKeyEncryptionMethodGenerator
            encMethodGen = new BcPublicKeyKeyEncryptionMethodGenerator(rng.getPublicKey(6752245936421807937L));
        encDataGen.addMethod(encMethodGen);

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        OutputStream cOut = encDataGen.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPEdDSATest());
    }
}
