package org.spongycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.x9.X962Parameters;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9ECPoint;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;

class ECUtils
{
    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPublicKey) ? ((BCECPublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
    }

    static X962Parameters getDomainParametersFromName(ECParameterSpec ecSpec, boolean withCompression)
    {
        X962Parameters params;

        if (ecSpec instanceof ECNamedCurveParameterSpec)
        {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveParameterSpec)ecSpec).getName());

            if (curveOid == null)
            {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveParameterSpec)ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            ECParameterSpec p = (ECParameterSpec)ecSpec;

            X9ECParameters ecP = new X9ECParameters(
                p.getCurve(), new X9ECPoint(p.getG(), withCompression), p.getN(), p.getH(), p.getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }
}
