package org.spongycastle.jcajce.provider.asymmetric.edec;

import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.X448PublicKeyParameters;

class BC11XDHPublicKey
    extends BCXDHPublicKey
    implements XECPublicKey
{
    BC11XDHPublicKey(AsymmetricKeyParameter pubKey)
    {
        super(pubKey);
    }

    BC11XDHPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        super(keyInfo);
    }

    BC11XDHPublicKey(byte[] prefix, byte[] rawData)
        throws InvalidKeySpecException
    {
        super(prefix, rawData);
    }

    public AlgorithmParameterSpec getParams()
    {
        if (xdhPublicKey instanceof X448PublicKeyParameters)
        {
            return NamedParameterSpec.X448;
        }
        else
        {
            return NamedParameterSpec.X25519;
        }
    }
}
