package org.spongycastle.jsse.provider;

import java.util.List;

import org.spongycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_9
    extends ExportSSLSession_8
{
    ExportSSLSession_9(BCExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @Override
    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
