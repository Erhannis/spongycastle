package org.spongycastle.openpgp.test;

import java.security.Security;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new BcPGPKeyRingTest(),
        new PGPKeyRingTest(),
        new BcPGPRSATest(),
        new PGPRSATest(),
        new BcPGPDSATest(),
        new PGPDSATest(),
        new BcPGPDSAElGamalTest(),
        new PGPDSAElGamalTest(),
        new BcPGPPBETest(),
        new PGPPBETest(),
        new PGPMarkerTest(),
        new PGPPacketTest(),
        new PGPArmoredTest(),
        new PGPSignatureTest(),
        new PGPClearSignedSignatureTest(),
        new PGPCompressionTest(),
        new PGPNoPrivateKeyTest(),
        new PGPECDSATest(),
        new PGPECDHTest(),
        new PGPECMessageTest(),
        new PGPParsingTest(),
        new PGPEdDSATest(),
        new SExprTest(),
        new ArmoredInputStreamTest(),
        new PGPUtilTest(),
        new RewindStreamWhenDecryptingMultiSKESKMessageTest(),
        new PGPFeaturesTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());

        SimpleTest.runTests(tests);
    }
}
