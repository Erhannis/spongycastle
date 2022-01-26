package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.spongycastle.crypto.signers.Ed25519Signer;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsStreamSigner;

public class BcTlsEd25519Signer
    extends BcTlsSigner
{
    public BcTlsEd25519Signer(BcTlsCrypto crypto, Ed25519PrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.ed25519)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);

        return new BcTlsStreamSigner(signer);
    }
}
