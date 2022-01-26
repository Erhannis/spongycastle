package org.spongycastle.tls;

import org.spongycastle.tls.crypto.TlsCrypto;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(TlsCrypto crypto)
    {
        super(crypto, ConnectionEnd.client);
    }

    public boolean isServer()
    {
        return false;
    }
}
