package org.spongycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;

import org.spongycastle.jcajce.PKIXCertRevocationChecker;
import org.spongycastle.jcajce.PKIXCertRevocationCheckerParameters;

class WrappedRevocationChecker
    implements PKIXCertRevocationChecker
{
    private final PKIXCertPathChecker checker;

    public WrappedRevocationChecker(PKIXCertPathChecker checker)
    {
        this.checker = checker;
    }

    public void setParameter(String name, Object value)
    {
         // ignore.
    }

    public void initialize(PKIXCertRevocationCheckerParameters params)
        throws CertPathValidatorException
    {
        checker.init(false);
    }

    public void check(Certificate cert)
        throws CertPathValidatorException
    {
        checker.check(cert);
    }
}
