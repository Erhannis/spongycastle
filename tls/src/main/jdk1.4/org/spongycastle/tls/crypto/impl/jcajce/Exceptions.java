package org.spongycastle.tls.crypto.impl.jcajce;

class Exceptions
{
    static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new org.spongycastle.tls.exception.IllegalStateException(message, cause);
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new org.spongycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
