package org.spongycastle.tls.crypto.impl.bc;

import org.spongycastle.crypto.ExtendedDigest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.tls.crypto.TlsHMAC;

final class BcTlsHMAC
    implements TlsHMAC
{
    private final HMac hmac;

    BcTlsHMAC(HMac hmac)
    {
        this.hmac = hmac;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        hmac.init(new KeyParameter(key, keyOff, keyLen));
    }

    public void update(byte[] input, int inOff, int length)
    {
        hmac.update(input, inOff, length);
    }

    public byte[] calculateMAC()
    {
        byte[] rv = new byte[hmac.getMacSize()];

        hmac.doFinal(rv, 0);

        return rv;
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        hmac.doFinal(output, outOff);
    }

    public int getInternalBlockSize()
    {
        return ((ExtendedDigest)hmac.getUnderlyingDigest()).getByteLength();
    }

    public int getMacLength()
    {
        return hmac.getMacSize();
    }

    public void reset()
    {
        hmac.reset();
    }
}
