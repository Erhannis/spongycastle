package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.engines.ChaCha7539Engine;
import org.spongycastle.crypto.macs.Poly1305;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Pack;

public class BcChaCha20Poly1305 implements TlsAEADCipherImpl
{
    private static final byte[] ZEROES = new byte[15];

    protected final ChaCha7539Engine cipher = new ChaCha7539Engine();
    protected final Poly1305 mac = new Poly1305();

    protected final boolean isEncrypting;

    protected int additionalDataLength;

    public BcChaCha20Poly1305(boolean isEncrypting)
    {
        this.isEncrypting = isEncrypting;
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        throws IOException
    {
        if (isEncrypting)
        {
            int ciphertextLength = inputLength;

            int outputLength = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);
            if (ciphertextLength != outputLength)
            {
                throw new IllegalStateException();
            }

            updateMAC(output, outputOffset, ciphertextLength);

            byte[] lengths = new byte[16];
            Pack.longToLittleEndian(additionalDataLength & 0xFFFFFFFFL, lengths, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, lengths, 8);
            mac.update(lengths, 0, 16);

            mac.doFinal(output, outputOffset + ciphertextLength);

            return ciphertextLength + 16;
        }
        else
        {
            int ciphertextLength = inputLength - 16;

            updateMAC(input, inputOffset, ciphertextLength);

            byte[] expectedMac = new byte[16];
            Pack.longToLittleEndian(additionalDataLength & 0xFFFFFFFFL, expectedMac, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, expectedMac, 8);
            mac.update(expectedMac, 0, 16);
            mac.doFinal(expectedMac, 0);

            boolean badMac = !TlsUtils.constantTimeAreEqual(16, expectedMac, 0, input, inputOffset + ciphertextLength);
            if (badMac)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }

            int outputLength = cipher.processBytes(input, inputOffset, ciphertextLength, output, outputOffset);

            if (ciphertextLength != outputLength)
            {
                throw new IllegalStateException();
            }

            return ciphertextLength;
        }
    }

    public int getOutputSize(int inputLength)
    {
        return isEncrypting ? inputLength + 16 : inputLength - 16;
    }

    public void init(byte[] nonce, int macSize, byte[] additionalData) throws IOException
    {
        if (nonce == null || nonce.length != 12 || macSize != 16)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        cipher.init(isEncrypting, new ParametersWithIV(null, nonce));
        initMAC();
        if (additionalData == null)
        {
            this.additionalDataLength = 0;
        }
        else
        {
            this.additionalDataLength = additionalData.length;
            updateMAC(additionalData, 0, additionalData.length);
        }
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        KeyParameter cipherKey = new KeyParameter(key, keyOff, keyLen);
        cipher.init(isEncrypting, new ParametersWithIV(cipherKey, ZEROES, 0, 12));
    }

    protected void initMAC()
    {
        byte[] firstBlock = new byte[64];
        cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        mac.init(new KeyParameter(firstBlock, 0, 32));
        Arrays.fill(firstBlock, (byte)0);
    }

    protected void updateMAC(byte[] buf, int off, int len)
    {
        mac.update(buf, off, len);

        int partial = len % 16;
        if (partial != 0)
        {
            mac.update(ZEROES, 0, 16 - partial);
        }
    }
}
