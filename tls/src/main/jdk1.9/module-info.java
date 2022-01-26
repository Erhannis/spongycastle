module org.spongycastle.tls
{
    provides java.security.Provider with org.spongycastle.jsse.provider.BouncyCastleJsseProvider;
    
    requires java.logging;
    requires org.spongycastle.provider;
    requires org.spongycastle.util;

    exports org.spongycastle.jsse;
    exports org.spongycastle.tls;
    exports org.spongycastle.jsse.provider;
    exports org.spongycastle.jsse.java.security;
    exports org.spongycastle.jsse.util;
    exports org.spongycastle.tls.crypto;
    exports org.spongycastle.tls.crypto.impl;
    exports org.spongycastle.tls.crypto.impl.bc;
    exports org.spongycastle.tls.crypto.impl.jcajce;
    exports org.spongycastle.tls.crypto.impl.jcajce.srp;
}
