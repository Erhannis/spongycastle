package org.spongycastle.tls.crypto.test;

import java.security.SecureRandom;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JcaTlsCryptoTest
    extends TlsCryptoTest
{
    public JcaTlsCryptoTest()
    {
        super(new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom()));
    }
}
