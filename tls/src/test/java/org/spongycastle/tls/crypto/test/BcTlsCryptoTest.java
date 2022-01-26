package org.spongycastle.tls.crypto.test;

import java.security.SecureRandom;

import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class BcTlsCryptoTest
    extends TlsCryptoTest
{
    public BcTlsCryptoTest()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }
}
