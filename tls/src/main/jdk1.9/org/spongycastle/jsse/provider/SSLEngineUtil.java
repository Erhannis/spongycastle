package org.spongycastle.jsse.provider;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.spongycastle.jsse.BCExtendedSSLSession;
import org.spongycastle.jsse.BCSSLEngine;
import org.spongycastle.jsse.BCSSLParameters;

abstract class SSLEngineUtil
{
    static ProvSSLEngine create(ContextData contextData)
    {
        return new ProvSSLEngine_9(contextData);
    }

    static ProvSSLEngine create(ContextData contextData, String host, int port)
    {
        return new ProvSSLEngine_9(contextData, host, port);
    }

    static BCExtendedSSLSession importHandshakeSession(SSLEngine sslEngine)
    {
        if (sslEngine instanceof BCSSLEngine)
        {
            return ((BCSSLEngine)sslEngine).getBCHandshakeSession();
        }
        if (null != sslEngine)
        {
            SSLSession sslSession = sslEngine.getHandshakeSession();
            if (null != sslSession)
            {
                return SSLSessionUtil.importSSLSession(sslSession);
            }
        }
        return null;
    }

    static BCSSLParameters importSSLParameters(SSLEngine sslEngine)
    {
        if (sslEngine instanceof BCSSLEngine)
        {
            return ((BCSSLEngine)sslEngine).getParameters();
        }
        if (null == sslEngine)
        {
            return null;
        }

        SSLParameters sslParameters = sslEngine.getSSLParameters();
        if (null == sslParameters)
        {
            throw new RuntimeException("SSLEngine.getSSLParameters returned null");
        }

        return SSLParametersUtil.importSSLParameters(sslParameters);
    }
}
