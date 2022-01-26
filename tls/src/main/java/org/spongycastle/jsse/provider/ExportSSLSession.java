package org.spongycastle.jsse.provider;

import org.spongycastle.jsse.BCExtendedSSLSession;

interface ExportSSLSession
{
    BCExtendedSSLSession unwrap();
}
