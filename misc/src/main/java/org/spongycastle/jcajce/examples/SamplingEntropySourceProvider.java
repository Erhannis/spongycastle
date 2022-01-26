package org.spongycastle.jcajce.examples;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.prng.EntropySource;
import org.spongycastle.crypto.prng.EntropySourceProvider;
import org.spongycastle.crypto.prng.SP800SecureRandom;
import org.spongycastle.crypto.prng.SP800SecureRandomBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.io.Streams;

/**
 * A basic example for Unix style systems that just uses /dev/random. The idea is just to get something that
 * samples regularly. If /dev/random can block for a long time you might want to put the reading of it on
 * a separate thread.
 */
public class SamplingEntropySourceProvider
    implements EntropySourceProvider
{
    @Override
    public EntropySource get(int bitsRequired)
    {
        return new DevRandomChainedSource(bitsRequired);
    }

    private class DevRandomChainedSource
        implements EntropySource
    {
        private static final int MAX_SAMPLES = 1000;
        
        private final SP800SecureRandom drbg;
        private final int bitsRequired;

        private int samples;

        DevRandomChainedSource(int bitsRequired)
        {
            this.bitsRequired = bitsRequired;
            byte[] nonce = new byte[32];

            privilegedRead(nonce);

            drbg = new SP800SecureRandomBuilder(new SeededSecureRandom())
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .buildHMAC(new HMac(new SHA512Digest()), nonce, false);
        }

        @Override
        public boolean isPredictionResistant()
        {
            return true;
        }

        @Override
        public byte[] getEntropy()
        {
            byte[] rv = new byte[(bitsRequired + 7) / 8];

            synchronized (drbg)
            {
                if (++samples == MAX_SAMPLES)
                {
                    samples = 0;
                    drbg.reseed(null);
                }

                drbg.nextBytes(rv);

                return rv;
            }
        }

        @Override
        public int entropySize()
        {
            return bitsRequired;
        }
    }

    private static int privilegedRead(final byte[] data)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Integer>()
        {
            public Integer run()
            {
                try
                {
                    FileInputStream seedStream = new FileInputStream("/dev/random");

                    Streams.readFully(seedStream, data);

                    return data.length;
                }
                catch (IOException e)
                {
                    throw new InternalError("unable to read random source");
                }
            }
        });
    }

    private static class SeededSecureRandom
        implements EntropySourceProvider
    {
        @Override
        public EntropySource get(final int bitsRequired)
        {
            return new EntropySource()
            {
                @Override
                public boolean isPredictionResistant()
                {
                    return true;
                }

                @Override
                public byte[] getEntropy()
                {
                    synchronized (this)
                    {
                        byte[] data = new byte[(bitsRequired + 7) / 8];

                        privilegedRead(data);

                        return data;
                    }
                }

                @Override
                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }

    public static void main(String[] ags)
        throws Exception
    {
        System.setProperty("org.spongycastle.drbg.entropysource", "org.spongycastle.jcajce.examples.SamplingEntropySourceProvider");

        Provider prov = new BouncyCastleProvider();

        SecureRandom ran = SecureRandom.getInstance("DEFAULT", prov);

        byte[] out = new byte[32];

        for (int i = 0; i != 1024; i++)
        {
            ran.nextBytes(out);
        }

        System.err.println(Hex.toHexString(out));
    }
}
