package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.io.SignerOutputStream;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsStreamSigner;
import org.spongycastle.util.io.TeeOutputStream;

class BcVerifyingStreamSigner
    implements TlsStreamSigner
{
    private final Signer signer;
    private final Signer verifier;
    private final TeeOutputStream output;

    BcVerifyingStreamSigner(Signer signer, Signer verifier)
    {
        OutputStream outputSigner = new SignerOutputStream(signer);
        OutputStream outputVerifier = new SignerOutputStream(verifier);

        this.signer = signer;
        this.verifier = verifier;
        this.output = new TeeOutputStream(outputSigner, outputVerifier);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            byte[] signature = signer.generateSignature();
            if (verifier.verifySignature(signature))
            {
                return signature;
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
