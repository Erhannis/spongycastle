package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.spongycastle.tls.DigitallySigned;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsStreamVerifier;
import org.spongycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSVerifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
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

        return crypto.createStreamVerifier(sigName, pssSpec, signature.getSignature(), publicKey);
    }
}
