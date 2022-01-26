package org.spongycastle.jsse.provider;

import org.spongycastle.jsse.BCX509ExtendedTrustManager;

interface ExportX509TrustManager
{
    BCX509ExtendedTrustManager unwrap();
}
