package org.spongycastle.its.bc;

import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.its.ITSCertificate;
import org.spongycastle.its.ITSExplicitCertificateBuilder;
import org.spongycastle.its.ITSPublicEncryptionKey;
import org.spongycastle.its.operator.ITSContentSigner;
import org.spongycastle.oer.its.CertificateId;
import org.spongycastle.oer.its.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey,
        ECPublicKeyParameters encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
        }

        return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey), publicEncryptionKey);
    }
}
