package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.params.Ed448PrivateKeyParameters;
import org.spongycastle.crypto.signers.Ed448Signer;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsStreamSigner;

public class BcTlsEd448Signer
    extends BcTlsSigner
{
    public BcTlsEd448Signer(BcTlsCrypto crypto, Ed448PrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.ed448)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed448Signer signer = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        signer.init(true, privateKey);

        return new BcTlsStreamSigner(signer);
    }
}
