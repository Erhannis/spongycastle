package org.spongycastle.jsse.provider;

import javax.net.ssl.SSLSession;

interface ImportSSLSession
{
    SSLSession unwrap();
}
