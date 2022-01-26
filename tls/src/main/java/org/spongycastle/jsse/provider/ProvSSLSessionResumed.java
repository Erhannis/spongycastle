package org.spongycastle.jsse.provider;

import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SecurityParameters;
import org.spongycastle.tls.SessionParameters;
import org.spongycastle.tls.TlsSession;

class ProvSSLSessionResumed
    extends ProvSSLSessionHandshake
{
    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;

    ProvSSLSessionResumed(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, TlsSession tlsSession,
        JsseSessionParameters jsseSessionParameters)
    {
        super(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return sessionParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return tlsSession.getSessionID();
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    @Override
    protected org.spongycastle.tls.Certificate getLocalCertificateTLS()
    {
        return sessionParameters.getLocalCertificate();
    }

    @Override
    protected org.spongycastle.tls.Certificate getPeerCertificateTLS()
    {
        return sessionParameters.getPeerCertificate();
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return sessionParameters.getNegotiatedVersion();
    }

    @Override
    protected void invalidateTLS()
    {
        tlsSession.invalidate();
    }

    public boolean isValid()
    {
        return super.isValid() && tlsSession.isResumable();
    }
}
