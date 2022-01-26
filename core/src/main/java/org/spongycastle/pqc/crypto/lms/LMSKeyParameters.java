package org.spongycastle.pqc.crypto.lms;

import java.io.IOException;

import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.util.Encodable;

public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable
{
    protected LMSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded()
        throws IOException;
}
