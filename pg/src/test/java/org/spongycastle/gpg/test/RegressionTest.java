package org.spongycastle.gpg.test;

import java.security.Security;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new KeyBoxTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        SimpleTest.runTests(tests);
    }
}
