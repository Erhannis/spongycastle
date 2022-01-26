package org.spongycastle.crypto.test;

import java.security.SecureRandom;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.spongycastle.crypto.agreement.X25519Agreement;
import org.spongycastle.crypto.generators.X25519KeyPairGenerator;
import org.spongycastle.crypto.params.X25519KeyGenerationParameters;
import org.spongycastle.util.test.SimpleTest;

public class X25519Test
    extends SimpleTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public String getName()
    {
        return "X25519";
    }

    public static void main(String[] args)
    {
        runTest(new X25519Test());
    }

    public void performTest()
    {
        for (int i = 0; i < 10; ++i)
        {
            testAgreement();
        }
    }

    private void testAgreement()
    {
        AsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
        kpGen.init(new X25519KeyGenerationParameters(RANDOM));

        AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
        AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();

        X25519Agreement agreeA = new X25519Agreement();
        agreeA.init(kpA.getPrivate());
        byte[] secretA = new byte[agreeA.getAgreementSize()];
        agreeA.calculateAgreement(kpB.getPublic(), secretA, 0);

        X25519Agreement agreeB = new X25519Agreement();
        agreeB.init(kpB.getPrivate());
        byte[] secretB = new byte[agreeB.getAgreementSize()];
        agreeB.calculateAgreement(kpA.getPublic(), secretB, 0);

        if (!areEqual(secretA, secretB))
        {
            fail("X25519 agreement failed");
        }
    }
}
