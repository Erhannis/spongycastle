package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.spongycastle.jcajce.io.OutputStreamFactory;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsStreamVerifier;

class JcaTlsStreamVerifier
    implements TlsStreamVerifier
{
    private final Signature verifier;
    private final OutputStream output;
    private final byte[] signature;

    JcaTlsStreamVerifier(Signature verifier, byte[] signature)
    {
        this.verifier = verifier;
        this.output = OutputStreamFactory.createStream(verifier);
        this.signature = signature;
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public boolean isVerified() throws IOException
    {
        try
        {
            return verifier.verify(signature);
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
