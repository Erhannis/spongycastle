package org.spongycastle.pqc.jcajce.provider;

import org.spongycastle.jcajce.provider.config.ConfigurableProvider;
import org.spongycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.spongycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.spongycastle.pqc.asn1.PQCObjectIdentifiers;
import org.spongycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;

public class QTESLA
{
    private static final String PREFIX = "org.spongycastle.pqc.jcajce.provider" + ".qtesla.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.QTESLA", PREFIX + "QTESLAKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.QTESLA", PREFIX + "KeyPairGeneratorSpi");

            provider.addAlgorithm("Signature.QTESLA", PREFIX + "SignatureSpi$qTESLA");
            addSignatureAlgorithm(provider,"QTESLA-P-I", PREFIX + "SignatureSpi$PI", PQCObjectIdentifiers.qTESLA_p_I);
            addSignatureAlgorithm(provider,"QTESLA-P-III", PREFIX + "SignatureSpi$PIII", PQCObjectIdentifiers.qTESLA_p_III);

            AsymmetricKeyInfoConverter keyFact = new QTESLAKeyFactorySpi();
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_I, "QTESLA-P-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_III, "QTESLA-P-III", keyFact);
        }
    }
}
