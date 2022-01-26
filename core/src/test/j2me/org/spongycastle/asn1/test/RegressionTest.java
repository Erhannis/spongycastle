package org.spongycastle.asn1.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new CertificateTest(),
        new OCSPTest(),
        new OIDTest(),
        new PKCS10Test(),
        new PKCS12Test(),
        new X509NameTest(),
        new X500NameTest(),
        new X509ExtensionsTest(),
        new BitStringTest(),
        new MiscTest(),
        new X9Test(),
        new EncryptedPrivateKeyInfoTest(),
        new StringTest(),
        new DERApplicationSpecificTest(),
        new IssuingDistributionPointUnitTest(),
        new TargetInformationTest(),
        new SubjectKeyIdentifierTest(),
        new ParsingTest(),
        new GeneralNameTest(),
        new RFC4519Test()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
