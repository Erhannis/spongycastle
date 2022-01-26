package org.spongycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.its.operator.ECDSAEncoder;
import org.spongycastle.its.operator.ITSContentVerifierProvider;
import org.spongycastle.oer.OEREncoder;
import org.spongycastle.oer.its.Certificate;
import org.spongycastle.oer.its.IssuerIdentifier;
import org.spongycastle.oer.its.PublicEncryptionKey;
import org.spongycastle.oer.its.Signature;
import org.spongycastle.oer.its.template.IEEE1609dot2;
import org.spongycastle.operator.ContentVerifier;
import org.spongycastle.util.Encodable;

public class ITSCertificate
    implements Encodable
{
    private final Certificate certificate;

    public ITSCertificate(Certificate certificate)
    {
        this.certificate = certificate;
    }

    public IssuerIdentifier getIssuer()
    {
        return certificate.getCertificateBase().getIssuer();
    }

    public ITSValidityPeriod getValidityPeriod()
    {
        return new ITSValidityPeriod(certificate.getCertificateBase().getToBeSignedCertificate().getValidityPeriod());
    }

    /**
     * Return the certificate's public encryption key, if present.
     *
     * @return 
     */
    public ITSPublicEncryptionKey getPublicEncryptionKey()
    {
        PublicEncryptionKey encryptionKey = certificate.getCertificateBase().getToBeSignedCertificate().getEncryptionKey();

        if (encryptionKey != null)
        {
            return new ITSPublicEncryptionKey(encryptionKey);
        }

        return null;
    }

    public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        ContentVerifier contentVerifier = verifierProvider.get(certificate.getCertificateBase().getSignature().getChoice());

        OutputStream verOut = contentVerifier.getOutputStream();


        verOut.write(
            OEREncoder.toByteArray(certificate.getCertificateBase().getToBeSignedCertificate(),
                IEEE1609dot2.tbsCertificate));

        verOut.close();

        Signature sig = certificate.getCertificateBase().getSignature();

        return contentVerifier.verify(ECDSAEncoder.toX962(sig));
    }

    public Certificate toASN1Structure()
    {
        return certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return OEREncoder.toByteArray(certificate.getCertificateBase(), IEEE1609dot2.certificate);
    }
}
