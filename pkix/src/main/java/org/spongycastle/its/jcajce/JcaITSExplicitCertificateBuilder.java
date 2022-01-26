package org.spongycastle.its.jcajce;

import java.security.Provider;
import java.security.interfaces.ECPublicKey;

import org.spongycastle.its.ITSCertificate;
import org.spongycastle.its.ITSExplicitCertificateBuilder;
import org.spongycastle.its.ITSPublicEncryptionKey;
import org.spongycastle.its.operator.ITSContentSigner;
import org.spongycastle.jcajce.util.DefaultJcaJceHelper;
import org.spongycastle.jcajce.util.JcaJceHelper;
import org.spongycastle.jcajce.util.NamedJcaJceHelper;
import org.spongycastle.jcajce.util.ProviderJcaJceHelper;
import org.spongycastle.oer.its.CertificateId;
import org.spongycastle.oer.its.ToBeSignedCertificate;

public class JcaITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    private JcaJceHelper helper;

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        this(signer, tbsCertificate, new DefaultJcaJceHelper());
    }

    private JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate, JcaJceHelper helper)
    {
        super(signer, tbsCertificate);
        this.helper = helper;
    }

    public JcaITSExplicitCertificateBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JcaITSExplicitCertificateBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);
        return this;
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey)
    {
        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey,
        ECPublicKey encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new JceITSPublicEncryptionKey(encryptionKey, helper);
        }

        return super.build(certificateId, new JcaITSPublicVerificationKey(verificationKey, helper), publicEncryptionKey);
    }
}
