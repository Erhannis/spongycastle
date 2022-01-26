package org.spongycastle.its.jcajce;

import java.security.Provider;

import org.spongycastle.its.ITSCertificate;
import org.spongycastle.its.ITSImplicitCertificateBuilder;
import org.spongycastle.oer.its.ToBeSignedCertificate;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaITSImplicitCertificateBuilderBuilder
{
    private JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

    public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider)
    {
        this.digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName)
    {
        this.digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public ITSImplicitCertificateBuilder build(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
        throws OperatorCreationException
    {
        return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(), tbsCertificate);
    }
}
