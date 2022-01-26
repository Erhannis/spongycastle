package org.spongycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPCompressedDataGenerator;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.UncloseableOutputStream;

public class PGPCompressionTest 
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        testCompression(new byte[0]);
        testCompression("hello world!".getBytes());

        SecureRandom random = new SecureRandom();
        byte[] randomData = new byte[1000000];
        random.nextBytes(randomData);

        testCompression(randomData);

        //
        // new style - using stream close
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        OutputStream out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

        out.write("hello world! !dlrow olleh".getBytes());

        out.close();

        validateData(bOut.toByteArray());

        try
        {
            out.close();
            cPacket.close();
        }
        catch (Exception e)
        {
            fail("Redundant close() should be ignored");
        }

        //
        // new style - using generator close
        //
        bOut = new ByteArrayOutputStream();
        cPacket = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

        out.write("hello world! !dlrow olleh".getBytes());

        cPacket.close();

        validateData(bOut.toByteArray());

        try
        {
            out.close();
            cPacket.close();
        }
        catch (Exception e)
        {
            fail("Redundant close() should be ignored");
        }
    }

    private void validateData(byte[] data)
        throws IOException, PGPException
    {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(data);
        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
        InputStream pIn = c1.getDataStream();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = pIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        if (!areEqual(bOut.toByteArray(), "hello world! !dlrow olleh".getBytes()))
        {
            fail("compression test failed");
        }
    }

    private void testCompression(byte[] data)
        throws IOException, PGPException
    {
        testCompression(data, PGPCompressedData.UNCOMPRESSED);
        testCompression(data, PGPCompressedData.ZIP);
        testCompression(data, PGPCompressedData.ZLIB);
        testCompression(data, PGPCompressedData.BZIP2);
    }

    private void testCompression(byte[] data, int type)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(type);

        OutputStream out = cPacket.open(new UncloseableOutputStream(bOut));

        out.write(data);

        out.close();

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());
        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
        InputStream pIn = c1.getDataStream();

        bOut.reset();

        int ch;
        while ((ch = pIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        if (!areEqual(bOut.toByteArray(), data))
        {
            fail("compression test failed");
        }
    }

    public String getName()
    {
        return "PGPCompressionTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPCompressionTest());
    }
}
