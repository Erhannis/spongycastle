package org.spongycastle.openpgp.operator;

import org.spongycastle.openpgp.PGPSessionKey;

public interface SessionKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    public abstract PGPSessionKey getSessionKey();
}
