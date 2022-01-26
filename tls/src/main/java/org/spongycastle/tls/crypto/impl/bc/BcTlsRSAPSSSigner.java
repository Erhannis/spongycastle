package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.engines.RSABlindedEngine;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.PSSSigner;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSSigner
    extends BcTlsSigner
{
    private final int signatureScheme;

    public BcTlsRSAPSSSigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        Digest digest = crypto.createDigest(cryptoHashAlgorithm);

        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), digest, digest.getDigestSize());
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));

        return new BcTlsStreamSigner(signer);
    }
}
