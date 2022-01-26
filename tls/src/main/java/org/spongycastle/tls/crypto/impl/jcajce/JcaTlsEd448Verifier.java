package org.spongycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import org.spongycastle.tls.SignatureAlgorithm;

public class JcaTlsEd448Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd448Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed448, "Ed448");
    }
}
