package org.spongycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CertificateEncodingException;

import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.jcajce.util.JcaJceHelper;

class X509CertificateInternal extends X509CertificateImpl
{
    private final byte[] encoding;
    private final CertificateEncodingException exception;

    X509CertificateInternal(JcaJceHelper bcHelper, org.spongycastle.asn1.x509.Certificate c,
        BasicConstraints basicConstraints, boolean[] keyUsage, String sigAlgName, byte[] sigAlgParams, byte[] encoding,
        CertificateEncodingException exception)
    {
        super(bcHelper, c, basicConstraints, keyUsage, sigAlgName, sigAlgParams);

        this.encoding = encoding;
        this.exception = exception;
    }

    public byte[] getEncoded() throws CertificateEncodingException
    {
        if (null != exception)
        {
            throw exception;
        }

        if (null == encoding)
        {
            throw new CertificateEncodingException();
        }

        return encoding;
    }
}
