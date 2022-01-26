package java.math.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BigIntegerTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
