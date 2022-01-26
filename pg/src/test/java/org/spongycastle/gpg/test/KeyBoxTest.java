package org.spongycastle.gpg.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Iterator;

import junit.framework.TestCase;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.gpg.keybox.BlobType;
import org.spongycastle.gpg.keybox.CertificateBlob;
import org.spongycastle.gpg.keybox.FirstBlob;
import org.spongycastle.gpg.keybox.KeyBlob;
import org.spongycastle.gpg.keybox.KeyBox;
import org.spongycastle.gpg.keybox.PublicKeyRingBlob;
import org.spongycastle.gpg.keybox.bc.BcBlobVerifier;
import org.spongycastle.gpg.keybox.bc.BcKeyBox;
import org.spongycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.util.io.Streams;
import org.spongycastle.util.test.SimpleTest;

public class KeyBoxTest
    extends SimpleTest
{
    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyBoxTest());
    }

    public String getName()
    {
        return "KeyBoxTest";
    }

    /**
     * Test loading a key store and extracting information.
     *
     * @throws Exception
     */
    public void testSuccessfulLoad()
        throws Exception
    {
        loadCheck(new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx")));
        loadCheck(new JcaKeyBoxBuilder().build(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx")));
    }

    private void loadCheck(KeyBox keyBox)
        throws Exception
    {

        FirstBlob firstBlob = keyBox.getFirstBlob();


        //
        // Check the first blob.
        //
        TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
        TestCase.assertEquals("Version", 1, firstBlob.getVersion());
        TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
        TestCase.assertEquals("Created at date.", 1526963333, firstBlob.getFileCreatedAt());
        TestCase.assertEquals("Last maintained date.", 1526963333, firstBlob.getLastMaintenanceRun());

        // Number of blobs.
        TestCase.assertEquals("Two material blobs.", 2, keyBox.getKeyBlobs().size());


        for (KeyBlob keyBlob : keyBox.getKeyBlobs())
        {

            switch (keyBlob.getType())
            {
            case X509_BLOB:
            {
                TestCase.assertEquals(2, keyBlob.getUserIds().size());
                TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());

                // Self signed.
                TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(0).getUserIDAsString());
                TestCase.assertEquals("CN=Peggy Shippen", keyBlob.getUserIds().get(1).getUserIDAsString());

                // It can be successfully parsed into a certificate.


                byte[] certData = ((CertificateBlob)keyBlob).getEncodedCertificate();
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                factory.generateCertificate(new ByteArrayInputStream(certData));

                TestCase.assertEquals(1, keyBlob.getKeyInformation().size());
                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
                TestCase.assertNull(keyBlob.getKeyInformation().get(0).getKeyID());
            }
            break;


            case OPEN_PGP_BLOB:
                TestCase.assertEquals(1, keyBlob.getUserIds().size());
                TestCase.assertEquals(keyBlob.getNumberOfUserIDs(), keyBlob.getUserIds().size());
                TestCase.assertEquals("Walter Mitty <walter@mitty.local>", keyBlob.getUserIds().get(0).getUserIDAsString());

                //
                // It can be successfully parsed.
                //
                ((PublicKeyRingBlob)keyBlob).getPGPPublicKeyRing();

                TestCase.assertEquals(2, keyBlob.getKeyInformation().size());
                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(0).getFingerprint().length);
                TestCase.assertNotNull(keyBlob.getKeyInformation().get(0).getKeyID());

                TestCase.assertEquals(20, keyBlob.getKeyInformation().get(1).getFingerprint().length);
                TestCase.assertNotNull(keyBlob.getKeyInformation().get(1).getKeyID());

                break;

            default:
                TestCase.fail("Unexpected blob type: " + keyBlob.getType());
            }
        }

    }

    /**
     * Test load kb with El Gamal keys in it.
     *
     * @throws Exception
     */
    public void testSanityElGamal()
        throws Exception
    {
        System.err.println("testSanityElGamal 1");
        try {
        testSanityElGamal_verify(new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/eg_pubring.kbx")));
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
        System.err.println("testSanityElGamal 2");
        testSanityElGamal_verify(new JcaKeyBoxBuilder().setProvider("BC").build(KeyBoxTest.class.getResourceAsStream("/pgpdata/eg_pubring.kbx")));
        System.err.println("testSanityElGamal 3");
    }

    private void testSanityElGamal_verify(KeyBox keyBox)
        throws Exception
    {
        System.err.println("testSanityElGamal_verify 1");
        FirstBlob firstBlob = keyBox.getFirstBlob();


        //
        // Check the first blob.
        //
        System.err.println("testSanityElGamal_verify 2");
        TestCase.assertEquals(BlobType.FIRST_BLOB, firstBlob.getType());
        TestCase.assertEquals("Version", 1, firstBlob.getVersion());
        TestCase.assertEquals("Header flags.", 2, firstBlob.getHeaderFlags());
        TestCase.assertEquals("Created at date.", 1527840866, firstBlob.getFileCreatedAt());
        TestCase.assertEquals("Last maintained date.", 1527840866, firstBlob.getLastMaintenanceRun());

        // Number of blobs.
        System.err.println("testSanityElGamal_verify 3");
        TestCase.assertEquals("One material blobs.", 1, keyBox.getKeyBlobs().size());

        System.err.println("testSanityElGamal_verify 4");
        TestCase.assertEquals("Pgp type", BlobType.OPEN_PGP_BLOB, keyBox.getKeyBlobs().get(0).getType());

        System.err.println("testSanityElGamal_verify 5");
        PublicKeyRingBlob pgkr = (PublicKeyRingBlob)keyBox.getKeyBlobs().get(0);
        PGPPublicKeyRing ring = pgkr.getPGPPublicKeyRing();

        System.err.println("testSanityElGamal_verify 6");
        TestCase.assertEquals("Must be DSA", PublicKeyAlgorithmTags.DSA, ring.getPublicKey().getAlgorithm());

        System.err.println("testSanityElGamal_verify 7");
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        it.next();
        TestCase.assertEquals("Must be ELGAMAL_ENCRYPT", PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, it.next().getAlgorithm());
        
        System.err.println("testSanityElGamal_verify done");
    }


    /**
     * Induce a checksum failure in the first key block.
     *
     * @throws Exception
     */
    public void testInducedChecksumFailed()
        throws Exception
    {

        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"));

        raw[36] ^= 1; // Single bit error in first key block.


        // BC
        try
        {
            System.err.println("Blob 1.1");
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            System.err.println("Blob 1.2");
            fail("Must have invalid checksum");
            System.err.println("Blob 1.3");
        }
        catch (IOException ioex)
        {
            System.err.println("Blob 1.4");
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
            System.err.println("Blob 1.5");
        }

        // JCA
        try
        {
            System.err.println("Blob 2.1");
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            System.err.println("Blob 2.2");
            fail("Must have invalid checksum");
            System.err.println("Blob 2.3");
        }
        catch (IOException ioex)
        {
            System.err.println("Blob 2.4");
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
            System.err.println("Blob 2.5");
        }

    }


    public void testBrokenMagic()
        throws Exception
    {
        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/pubring.kbx"));

        raw[8] ^= 1; // Single bit error in magic number.

        // BC
        try
        {
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must have invalid magic");
        }
        catch (IOException ioex)
        {
            isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.getMessage());
        }


        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            fail("Must have invalid checksum");
        }
        catch (IOException ioex)
        {
            isEquals("Incorrect magic expecting 4b425866 but got 4a425866", ioex.getMessage());
        }
    }

    public void testNullSource()
        throws Exception
    {
        InputStream zulu = null;

        // BC
        try
        {
            new KeyBox(zulu, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IllegalArgumentException ioex)
        {
            isEquals("Cannot take get instance of null", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(zulu);
            fail("Must fail.");
        }
        catch (IllegalArgumentException ioex)
        {
            isEquals("Cannot take get instance of null", ioex.getMessage());
        }

    }


    public void testNoFirstBlob()
        throws Exception
    {
        // BC
        try
        {
            new KeyBox(new byte[0], new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("No first blob, is the source zero length?", ioex.getMessage());
        }

        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(new byte[0]);
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("No first blob, is the source zero length?", ioex.getMessage());
        }

    }

    public void testDoubleFirstBlob()
        throws Exception
    {
        // BC
        try
        {
            new KeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/doublefirst.kbx"), new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.getMessage());
        }


        // JCA
        try
        {
            new JcaKeyBoxBuilder().setProvider("BC").build(KeyBoxTest.class.getResourceAsStream("/pgpdata/doublefirst.kbx"));
            fail("Must fail.");
        }
        catch (IOException ioex)
        {
            isEquals("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.", ioex.getMessage());
        }
    }

    public void testKeyBoxWithMD5Sanity()
        throws Exception
    {
        //
        // Expect no failure.
        //
        new BcKeyBox(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));
        new JcaKeyBoxBuilder().build(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));
    }

    public void testKeyBoxWithBrokenMD5()
        throws Exception
    {
        byte[] raw = Streams.readAll(KeyBoxTest.class.getResourceAsStream("/pgpdata/md5kbx.kbx"));

        raw[36] ^= 1; // Single bit error in first key block.

        // BC
        try
        {
            System.err.println("Blob 3.1");
            new KeyBox(raw, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
            System.err.println("Blob 3.2");
            fail("Must have invalid checksum");
            System.err.println("Blob 3.3");
        }
        catch (IOException ioex)
        {
            System.err.println("Blob 3.4");
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
            System.err.println("Blob 3.5");
        }

        // JCA
        try
        {
            System.err.println("Blob 4.1");
            new JcaKeyBoxBuilder().setProvider("BC").build(raw);
            System.err.println("Blob 4.2");
            fail("Must have invalid checksum");
            System.err.println("Blob 4.3");
        }
        catch (IOException ioex)
        {
            System.err.println("Blob 4.4");
            isEquals("Blob with base offset of 32 has incorrect digest.", ioex.getMessage());
            System.err.println("Blob 4.5");
        }


    }


    public void performTest()
        throws Exception
    {
        System.err.println("performTest testNoFirstBlob");
        testNoFirstBlob();
        System.err.println("performTest testSanityElGamal");
        testSanityElGamal();
        System.err.println("performTest testKeyBoxWithBrokenMD5");
        testKeyBoxWithBrokenMD5();
        System.err.println("performTest testKeyBoxWithMD5Sanity");
        testKeyBoxWithMD5Sanity();
        System.err.println("performTest testDoubleFirstBlob");
        testDoubleFirstBlob();
        System.err.println("performTest testNullSource");
        testNullSource();
        System.err.println("performTest testBrokenMagic");
        testBrokenMagic();
        System.err.println("performTest testSuccessfulLoad");
        testSuccessfulLoad();
        System.err.println("performTest testInducedChecksumFailed");
        testInducedChecksumFailed();
        System.err.println("performTest done");
    }


}
