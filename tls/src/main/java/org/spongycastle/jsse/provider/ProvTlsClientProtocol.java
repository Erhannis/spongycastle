package org.spongycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.spongycastle.tls.RenegotiationPolicy;
import org.spongycastle.tls.TlsClientProtocol;

class ProvTlsClientProtocol extends TlsClientProtocol
{
    private static final boolean provAcceptRenegotiation = PropertyUtils.getBooleanSystemProperty(
        "org.spongycastle.jsse.client.acceptRenegotiation", false);

    private final Closeable closeable;

    ProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable)
    {
        super(input, output);

        this.closeable = closeable;
    }

    @Override
    protected void closeConnection() throws IOException
    {
        closeable.close();
    }

    @Override
    protected int getRenegotiationPolicy()
    {
        return provAcceptRenegotiation ? RenegotiationPolicy.ACCEPT : RenegotiationPolicy.DENY;
    }
}
