package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.modes.AEADBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.impl.TlsAEADCipherImpl;

final class BcTlsAEADCipherImpl
    implements TlsAEADCipherImpl
{
    private final boolean isEncrypting;
    private final AEADBlockCipher cipher;

    private KeyParameter key;

    BcTlsAEADCipherImpl(AEADBlockCipher cipher, boolean isEncrypting)
    {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void init(byte[] nonce, int macSize, byte[] additionalData)
    {
        cipher.init(isEncrypting, new AEADParameters(key, macSize * 8, nonce, additionalData));
    }

    public int getOutputSize(int inputLength)
    {
        return cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        throws IOException
    {
        int len = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);

        try
        {
            len += cipher.doFinal(output, outputOffset + len);
        }
        catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        return len;
    }
}
