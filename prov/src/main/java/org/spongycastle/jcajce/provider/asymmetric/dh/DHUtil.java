package org.spongycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;

import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Fingerprint;
import org.spongycastle.util.Strings;

class DHUtil
{
    static String privateKeyToString(String algorithm, BigInteger x, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("              Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("             Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, DHParameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getG().toByteArray())).toString();
    }
}
