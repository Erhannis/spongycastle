package org.spongycastle.its.bc;

import org.spongycastle.its.ITSCertificate;
import org.spongycastle.its.ITSImplicitCertificateBuilder;
import org.spongycastle.oer.its.ToBeSignedCertificate;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}
