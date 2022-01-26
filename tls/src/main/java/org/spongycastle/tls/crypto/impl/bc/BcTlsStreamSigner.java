package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.io.SignerOutputStream;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsStreamSigner;

class BcTlsStreamSigner
    implements TlsStreamSigner
{
    private final SignerOutputStream output;

    BcTlsStreamSigner(Signer signer)
    {
        this.output = new SignerOutputStream(signer);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return output.getSigner().generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
