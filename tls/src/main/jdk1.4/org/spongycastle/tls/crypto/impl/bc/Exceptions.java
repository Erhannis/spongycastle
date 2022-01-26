package org.spongycastle.tls.crypto.impl.bc;

class Exceptions
{
    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new org.spongycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
