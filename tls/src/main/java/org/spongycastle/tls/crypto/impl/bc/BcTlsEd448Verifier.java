package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.params.Ed448PublicKeyParameters;
import org.spongycastle.crypto.signers.Ed448Signer;
import org.spongycastle.tls.DigitallySigned;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd448Verifier
    extends BcTlsVerifier
{
    public BcTlsEd448Verifier(BcTlsCrypto crypto, Ed448PublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.ed448)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed448Signer verifier = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
