package org.spongycastle.tls.crypto.impl.bc;

import java.math.BigInteger;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.agreement.srp.SRP6Client;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsSRP6Client;

final class BcTlsSRP6Client
    implements TlsSRP6Client
{
    private final SRP6Client srp6Client;

    BcTlsSRP6Client(SRP6Client srpClient)
    {
        this.srp6Client = srpClient;
    }

    public BigInteger calculateSecret(BigInteger serverB)
        throws TlsFatalAlert
    {
        try
        {
            return srp6Client.calculateSecret(serverB);
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public BigInteger generateClientCredentials(byte[] srpSalt, byte[] identity, byte[] password)
    {
        return srp6Client.generateClientCredentials(srpSalt, identity, password);
    }
}
