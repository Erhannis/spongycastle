package org.spongycastle.tls;

public interface TlsHeartbeat
{
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}
