package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.params.Ed25519PublicKeyParameters;
import org.spongycastle.crypto.signers.Ed25519Signer;
import org.spongycastle.tls.DigitallySigned;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd25519Verifier
    extends BcTlsVerifier
{
    public BcTlsEd25519Verifier(BcTlsCrypto crypto, Ed25519PublicKeyParameters publicKey)
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
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.ed25519)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
