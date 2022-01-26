package org.spongycastle.tls;

import org.spongycastle.tls.crypto.TlsSecret;

public interface TlsPSK
{
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}
