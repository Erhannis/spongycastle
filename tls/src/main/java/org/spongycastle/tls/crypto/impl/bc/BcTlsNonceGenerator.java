package org.spongycastle.tls.crypto.impl.bc;

import org.spongycastle.crypto.prng.RandomGenerator;
import org.spongycastle.tls.crypto.TlsNonceGenerator;

final class BcTlsNonceGenerator
    implements TlsNonceGenerator
{
    private final RandomGenerator randomGenerator;

    BcTlsNonceGenerator(RandomGenerator randomGenerator)
    {
        this.randomGenerator = randomGenerator;
    }

    public byte[] generateNonce(int size)
    {
        byte[] nonce = new byte[size];
        randomGenerator.nextBytes(nonce);
        return nonce;
    }
}
