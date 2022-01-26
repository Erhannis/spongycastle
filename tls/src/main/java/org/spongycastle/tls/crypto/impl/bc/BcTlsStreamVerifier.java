package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.io.SignerOutputStream;
import org.spongycastle.tls.crypto.TlsStreamVerifier;

class BcTlsStreamVerifier
    implements TlsStreamVerifier
{
    private final SignerOutputStream output;
    private final byte[] signature;

    BcTlsStreamVerifier(Signer verifier, byte[] signature)
    {
        this.output = new SignerOutputStream(verifier);
        this.signature = signature;
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public boolean isVerified() throws IOException
    {
        return output.getSigner().verifySignature(signature);
    }
}
