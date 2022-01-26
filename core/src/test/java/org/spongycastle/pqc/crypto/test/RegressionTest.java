package org.spongycastle.pqc.crypto.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new GMSSSignerTest(),
        new McElieceFujisakiCipherTest(),
        new McElieceKobaraImaiCipherTest(),
        new McElieceCipherTest(),
        new McEliecePointchevalCipherTest(),
        new RainbowSignerTest() ,
        new Sphincs256Test(),
        new NewHopeTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
