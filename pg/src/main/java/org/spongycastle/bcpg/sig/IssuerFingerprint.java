package org.spongycastle.bcpg.sig;

import org.spongycastle.bcpg.SignatureSubpacket;
import org.spongycastle.bcpg.SignatureSubpacketTags;
import org.spongycastle.util.Arrays;

/**
 * packet giving the issuer key fingerprint.
 */
public class IssuerFingerprint
    extends SignatureSubpacket
{
    public IssuerFingerprint(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, isLongLength, data);
    }

    public IssuerFingerprint(
        boolean    critical,
        int        keyVersion,
        byte[]     fingerprint)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, false,
                    Arrays.concatenate(new byte[] { (byte)keyVersion }, fingerprint));
    }

    public int getKeyVersion()
    {
        return data[0] & 0xff;
    }

    public byte[] getFingerprint()
    {
        return Arrays.copyOfRange(data, 1, data.length);
    }
}
