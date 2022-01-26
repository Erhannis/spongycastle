package org.spongycastle.tls.crypto.impl;

import org.spongycastle.tls.ExporterLabel;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SecurityParameters;
import org.spongycastle.tls.crypto.TlsCryptoParameters;
import org.spongycastle.tls.crypto.TlsSecret;
import org.spongycastle.util.Arrays;

/**
 * Useful utility methods.
 */
public class TlsImplUtils
{
    public static boolean isSSL(TlsCryptoParameters cryptoParams)
    {
        return cryptoParams.getServerVersion().isSSL();
    }

    public static boolean isTLSv10(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsCryptoParameters cryptoParams)
    {
        return isTLSv10(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsCryptoParameters cryptoParams)
    {
        return isTLSv11(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsCryptoParameters cryptoParams)
    {
        return isTLSv12(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsCryptoParameters cryptoParams)
    {
        return isTLSv13(cryptoParams.getServerVersion());
    }

    public static byte[] calculateKeyBlock(TlsCryptoParameters cryptoParams, int length)
    {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        TlsSecret master_secret = securityParameters.getMasterSecret();
        byte[] seed = Arrays.concatenate(securityParameters.getServerRandom(), securityParameters.getClientRandom());
        return PRF(securityParameters, master_secret, ExporterLabel.key_expansion, seed, length).extract();
    }

    public static TlsSecret PRF(SecurityParameters securityParameters, TlsSecret secret, String asciiLabel, byte[] seed,
        int length)
    {
        return secret.deriveUsingPRF(securityParameters.getPRFAlgorithm(), asciiLabel, seed, length);
    }

    public static TlsSecret PRF(TlsCryptoParameters cryptoParams, TlsSecret secret, String asciiLabel, byte[] seed,
        int length)
    {
        return PRF(cryptoParams.getSecurityParametersHandshake(), secret, asciiLabel, seed, length);
    }
}
