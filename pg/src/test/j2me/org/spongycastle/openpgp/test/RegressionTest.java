package org.spongycastle.openpgp.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BcPGPDSAElGamalTest(),
        new BcPGPDSATest(),
        new BcPGPKeyRingTest(),
        new BcPGPPBETest(),
        new BcPGPRSATest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
