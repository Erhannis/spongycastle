package org.spongycastle.its;

import org.spongycastle.oer.its.PublicEncryptionKey;
import org.spongycastle.oer.its.SymmAlgorithm;

public class ITSPublicEncryptionKey
{
    protected final PublicEncryptionKey encryptionKey;

    public ITSPublicEncryptionKey(PublicEncryptionKey encryptionKey)
    {
        this.encryptionKey = encryptionKey;
    }

    public enum symmAlgorithm
    {
        aes128Ccm(SymmAlgorithm.aes128Ccm.intValueExact());

        private final int tagValue;

        symmAlgorithm(int tagValue)
        {
            this.tagValue = tagValue;
        }
    }

    public PublicEncryptionKey toASN1Structure()
    {
        return encryptionKey;
    }
}
