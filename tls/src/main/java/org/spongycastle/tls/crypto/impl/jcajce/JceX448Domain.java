package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.spongycastle.asn1.edec.EdECObjectIdentifiers;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsAgreement;
import org.spongycastle.tls.crypto.TlsCryptoException;
import org.spongycastle.tls.crypto.TlsECDomain;
import org.spongycastle.util.Arrays;

public class JceX448Domain implements TlsECDomain
{
    protected final JcaTlsCrypto crypto;

    public JceX448Domain(JcaTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey)
        throws IOException
    {
        try
        {
            byte[] secret = crypto.calculateKeyAgreement("X448", privateKey, publicKey, "TlsPremasterSecret");

            if (secret == null || secret.length != 56)
            {
                throw new TlsCryptoException("invalid secret calculated");
            }
            if (Arrays.areAllZeroes(secret, 0, secret.length))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public TlsAgreement createECDH()
    {
        return new JceX448(this);
    }

    public PublicKey decodePublicKey(byte[] encoding) throws IOException
    {
        return XDHUtil.decodePublicKey(crypto, "X448", EdECObjectIdentifiers.id_X448, encoding);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException
    {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("X448");
            keyPairGenerator.initialize(448, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}
