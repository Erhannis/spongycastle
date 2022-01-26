package org.spongycastle.tls.crypto.impl.bc;

import org.spongycastle.tls.crypto.TlsAgreement;
import org.spongycastle.tls.crypto.TlsECDomain;

public class BcX25519Domain implements TlsECDomain
{
    protected final BcTlsCrypto crypto;

    public BcX25519Domain(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public TlsAgreement createECDH()
    {
        return new BcX25519(crypto);
    }
}
