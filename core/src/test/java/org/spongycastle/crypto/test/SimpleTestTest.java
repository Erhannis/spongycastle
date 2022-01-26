package org.spongycastle.crypto.test;

import junit.framework.TestCase;
import org.spongycastle.util.test.SimpleTestResult;

public class SimpleTestTest
    extends TestCase
{
    public void testCrypto()
    {
        org.spongycastle.util.test.Test[] tests = RegressionTest.tests;

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail(result.toString());
            }
        }
    }
}

