package org.spongycastle.gpg.keybox.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.spongycastle.gpg.keybox.BlobVerifier;
import org.spongycastle.gpg.keybox.KeyBox;
import org.spongycastle.openpgp.operator.KeyFingerPrintCalculator;

public class JcaKeyBox
    extends KeyBox
{
    JcaKeyBox(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException
    {
        super(encoding, fingerPrintCalculator, verifier);
    }

    JcaKeyBox(InputStream input, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException
    {
        super(input, fingerPrintCalculator, verifier);
    }
}
