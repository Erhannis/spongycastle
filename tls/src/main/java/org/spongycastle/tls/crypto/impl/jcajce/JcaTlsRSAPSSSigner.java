package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsSigner;
import org.spongycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSSigner
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSSigner(JcaTlsCrypto crypto, PrivateKey privateKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        String digestName = crypto.getDigestName(cryptoHashAlgorithm);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName,
            crypto.getHelper());

        return crypto.createStreamSigner(sigName, pssSpec, privateKey, true);
    }
}
