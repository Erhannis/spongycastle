#!/bin/sh
# script to remove JDK 1.5+ generics from a file

(
ed $1 <<%%
g/java.security.cert.CertStore/s//org.spongycastle.jce.cert.CertStore/
g/java.security.cert.PKIX/s//org.spongycastle.jce.cert.PKIX/
g/java.security.cert.CertPath/s//org.spongycastle.jce.cert.CertPath/
g/java.security.cert.X509CertSelector/s//org.spongycastle.jce.cert.X509CertSelector/
g/java.security.cert.X509CRLSelector/s//org.spongycastle.jce.cert.X509CRLSelector/
g/java.security.cert.CertSelector/s//org.spongycastle.jce.cert.CertSelector/
g/java.security.cert.CRLSelector/s//org.spongycastle.jce.cert.CRLSelector/
g/java.security.cert.TrustAnchor/s//org.spongycastle.jce.cert.TrustAnchor/
w
q
%%
) > /dev/null 2>&1
