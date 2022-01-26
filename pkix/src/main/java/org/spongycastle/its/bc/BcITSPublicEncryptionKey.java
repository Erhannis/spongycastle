package org.spongycastle.its.bc;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.sec.SECObjectIdentifiers;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ECNamedDomainParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.its.ITSPublicEncryptionKey;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.oer.its.BasePublicEncryptionKey;
import org.spongycastle.oer.its.EccCurvePoint;
import org.spongycastle.oer.its.EccP256CurvePoint;
import org.spongycastle.oer.its.EccP384CurvePoint;
import org.spongycastle.oer.its.PublicEncryptionKey;
import org.spongycastle.oer.its.SymmAlgorithm;

public class BcITSPublicEncryptionKey
    extends ITSPublicEncryptionKey
{
    public BcITSPublicEncryptionKey(PublicEncryptionKey encryptionKey)
    {
        super(encryptionKey);
    }

    static PublicEncryptionKey fromKeyParameters(ECPublicKeyParameters pubKey)
    {
        ASN1ObjectIdentifier curveID = ((ECNamedDomainParameters)pubKey.getParameters()).getName();
        ECPoint q  = pubKey.getQ();
        
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesNistP256)
                    .setValue(EccP256CurvePoint.builder()
                        .createUncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()))
                    .createBasePublicEncryptionKey());
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesBrainpoolP256r1)
                    .setValue(EccP256CurvePoint.builder()
                        .createUncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()))
                    .createBasePublicEncryptionKey());
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public BcITSPublicEncryptionKey(AsymmetricKeyParameter encryptionKey)
    {
        super(fromKeyParameters((ECPublicKeyParameters)encryptionKey));
    }

    public AsymmetricKeyParameter getKey()
    {
        X9ECParameters params;

        BasePublicEncryptionKey baseKey = encryptionKey.getBasePublicEncryptionKey();
        ASN1ObjectIdentifier curveID;

        switch (baseKey.getChoice())
        {
        case BasePublicEncryptionKey.eciesNistP256:
            curveID = SECObjectIdentifiers.secp256r1;
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case BasePublicEncryptionKey.eciesBrainpoolP256r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = encryptionKey.getBasePublicEncryptionKey().getValue();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)baseKey.getValue();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        return new ECPublicKeyParameters(point,
            new ECNamedDomainParameters(curveID, params));
    }
}
