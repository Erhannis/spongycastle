package org.spongycastle.asn1.test;

import org.spongycastle.util.test.SimpleTest;
import org.spongycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new InputStreamTest(),
        new EqualsAndHashCodeTest(),
        new TagTest(),
        new SetTest(),
        new DERUTF8StringTest(),
        new CertificateTest(),
        new GenerationTest(),
        new OCSPTest(),
        new OIDTest(),
        new PKCS10Test(),
        new PKCS12Test(),
        new X509NameTest(),
        new X500NameTest(),
        new X509ExtensionsTest(),
        new GeneralizedTimeTest(),
        new BitStringTest(),
        new MiscTest(),
        new X9Test(),
        new MonetaryValueUnitTest(),
        new BiometricDataUnitTest(),
        new Iso4217CurrencyCodeUnitTest(),
        new SemanticsInformationUnitTest(),
        new QCStatementUnitTest(),
        new TypeOfBiometricDataUnitTest(),
        new EncryptedPrivateKeyInfoTest(),
        new ReasonFlagsTest(),
        new NetscapeCertTypeTest(),
        new KeyUsageTest(),
        new StringTest(),
        new UTCTimeTest(),
        new NameOrPseudonymUnitTest(),
        new PersonalDataUnitTest(),
        new DERApplicationSpecificTest(),
        new IssuingDistributionPointUnitTest(),
        new TargetInformationTest(),
        new SubjectKeyIdentifierTest(),
        new ParsingTest(),
        new GeneralNameTest(),
        new DERPrivateTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
