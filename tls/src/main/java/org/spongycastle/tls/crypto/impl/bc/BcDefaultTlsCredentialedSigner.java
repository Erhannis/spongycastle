package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.DSAPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.spongycastle.crypto.params.Ed448PrivateKeyParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.tls.Certificate;
import org.spongycastle.tls.DefaultTlsCredentialedSigner;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.SignatureScheme;
import org.spongycastle.tls.crypto.TlsCryptoParameters;
import org.spongycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.
 */
public class BcDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static BcTlsCertificate getEndEntity(BcTlsCrypto crypto, Certificate certificate) throws IOException
    {
        if (certificate == null || certificate.isEmpty())
        {
            throw new IllegalArgumentException("No certificate");
        }

        return BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
    }

    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters privKeyRSA = (RSAKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(signatureScheme))
                {
                    return new BcTlsRSAPSSSigner(crypto, privKeyRSA, signatureScheme);
                }
            }

            RSAKeyParameters pubKeyRSA;
            try
            {
                pubKeyRSA = getEndEntity(crypto, certificate).getPubKeyRSA();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }

            signer = new BcTlsRSASigner(crypto, privKeyRSA, pubKeyRSA);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            signer = new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            ECPrivateKeyParameters privKeyEC = (ECPrivateKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                // TODO[RFC 8998]
//                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
//                switch (signatureAlgorithm)
//                {
//                case SignatureAlgorithm.sm2:
//                    return new BcTlsSM2Signer(crypto, privKeyEC, Strings.toByteArray("TLSv1.3+GM+Cipher+Suite"));
//                }

                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isECDSA(signatureScheme))
                {
                    return new BcTlsECDSA13Signer(crypto, privKeyEC, signatureScheme);
                }
            }

            signer = new BcTlsECDSASigner(crypto, privKeyEC);
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            signer = new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            signer = new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
        AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
            signatureAndHashAlgorithm);
    }
}
