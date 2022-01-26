package org.spongycastle.openpgp.examples;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPPBEEncryptedData;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.util.io.Streams;

/**
 * A simple utility class that encrypts/decrypts password based
 * encryption files.
 * <p>
 * To encrypt a file: PBEFileProcessor -e [-ai] fileName passPhrase.<br>
 * If -a is specified the output file will be "ascii-armored".<br>
 * If -i is specified the output file will be "integrity protected".
 * <p>
 * To decrypt: PBEFileProcessor -d fileName passPhrase.
 * <p>
 * Note: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
 * will have been used.
 */
public class PBEFileProcessor
{
    private static void decryptFile(String inputFileName, char[] passPhrase)
        throws IOException, NoSuchProviderException, PGPException
    {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        decryptFile(in, passPhrase);
        in.close();
    }

    /*
     * decrypt the passed in message stream
     */
    private static void decryptFile(
        InputStream    in,
        char[]         passPhrase)
        throws IOException, NoSuchProviderException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);
        
        JcaPGPObjectFactory        pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList    enc;
        Object                  o = pgpF.nextObject();
        
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList)
        {
            enc = (PGPEncryptedDataList)o;
        }
        else
        {
            enc = (PGPEncryptedDataList)pgpF.nextObject();
        }

        PGPPBEEncryptedData     pbe = (PGPPBEEncryptedData)enc.get(0);

        InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(passPhrase));
        
        JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(clear);

        //
        // if we're trying to read a file generated by someone other than us
        // the data might not be compressed, so we check the return type from
        // the factory and behave accordingly.
        //
        o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData)
        {
            PGPCompressedData   cData = (PGPCompressedData)o;

            pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

            o = pgpFact.nextObject();
        }
        
        PGPLiteralData ld = (PGPLiteralData)o;
        InputStream unc = ld.getInputStream();

        OutputStream fOut = new FileOutputStream(ld.getFileName());

        Streams.pipeAll(unc, fOut, 8192);

        fOut.close();

        if (pbe.isIntegrityProtected())
        {
            if (!pbe.verify())
            {
                System.err.println("message failed integrity check");
            }
            else
            {
                System.err.println("message integrity check passed");
            }
        }
        else
        {
            System.err.println("no message integrity check");
        }
    }

    private static void encryptFile(
        String          outputFileName,
        String          inputFileName,
        char[]          passPhrase,
        boolean         armor,
        boolean         withIntegrityCheck)
        throws IOException, NoSuchProviderException
    {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        encryptFile(out, inputFileName, passPhrase, armor, withIntegrityCheck);
        out.close();
    }

    private static void encryptFile(
        OutputStream    out,
        String          fileName,
        char[]          passPhrase,
        boolean         armor,
        boolean         withIntegrityCheck)
        throws IOException, NoSuchProviderException
    {
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }

        try
        {
            byte[] compressedData = PGPExampleUtil.compressFile(fileName, CompressionAlgorithmTags.ZIP);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                .setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passPhrase).setProvider("BC"));

            OutputStream encOut = encGen.open(out, compressedData.length);

            encOut.write(compressedData);
            encOut.close();

            if (armor)
            {
                out.close();
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args[0].equals("-e"))
        {
            if (args[1].equals("-a") || args[1].equals("-ai") || args[1].equals("-ia"))
            {
                encryptFile(args[2] + ".asc", args[2], args[3].toCharArray(), true, (args[1].indexOf('i') > 0));
            }
            else if (args[1].equals("-i"))
            {
                encryptFile(args[2] + ".bpg", args[2], args[3].toCharArray(), false, true);
            }
            else
            {
                encryptFile(args[1] + ".bpg", args[1], args[2].toCharArray(), false, false);
            }
        }
        else if (args[0].equals("-d"))
        {
            decryptFile(args[1], args[2].toCharArray());
        }
        else
        {
            System.err.println("usage: PBEFileProcessor -e [-ai]|-d file passPhrase");
        }
    }
}
