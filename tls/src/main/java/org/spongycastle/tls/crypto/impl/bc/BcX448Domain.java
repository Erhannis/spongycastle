package org.spongycastle.tls.crypto.impl.bc;

import org.spongycastle.tls.crypto.TlsAgreement;
import org.spongycastle.tls.crypto.TlsECDomain;

public class BcX448Domain implements TlsECDomain
{
    protected final BcTlsCrypto crypto;

    public BcX448Domain(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public TlsAgreement createECDH()
    {
        return new BcX448(crypto);
    }
}
