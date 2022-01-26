package org.spongycastle.cert.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new AttrCertTest(),
        new AttrCertSelectorTest(),
        new CertTest(),
        new PKCS10Test()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
