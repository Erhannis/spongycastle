package org.spongycastle.jsse.provider;

import org.spongycastle.jsse.BCSSLConnection;
import org.spongycastle.tls.ChannelBinding;
import org.spongycastle.tls.TlsContext;

class ProvSSLConnection
    implements BCSSLConnection
{
    protected final TlsContext tlsContext;
    protected final ProvSSLSession session; 

    ProvSSLConnection(TlsContext tlsContext, ProvSSLSession session)
    {
        this.tlsContext = tlsContext;
        this.session = session;
    }

    public String getApplicationProtocol()
    {
        return JsseUtils.getApplicationProtocol(tlsContext.getSecurityParametersConnection());
    }

    public byte[] getChannelBinding(String channelBinding)
    {
        if (channelBinding.equals("tls-server-end-point"))
        {
            return tlsContext.exportChannelBinding(ChannelBinding.tls_server_end_point);
        }

        if (channelBinding.equals("tls-unique"))
        {
            return tlsContext.exportChannelBinding(ChannelBinding.tls_unique);
        }

        throw new UnsupportedOperationException();
    }

    public ProvSSLSession getSession()
    {
        return session;
    }
}
