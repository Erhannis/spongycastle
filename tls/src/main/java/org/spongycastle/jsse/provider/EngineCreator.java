package org.spongycastle.jsse.provider;

import java.security.GeneralSecurityException;

interface EngineCreator
{
    Object createInstance(Object constructorParameter)
        throws GeneralSecurityException;
}
