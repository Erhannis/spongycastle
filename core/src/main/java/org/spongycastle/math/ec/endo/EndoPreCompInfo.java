package org.spongycastle.math.ec.endo;

import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.PreCompInfo;

public class EndoPreCompInfo implements PreCompInfo
{
    protected ECEndomorphism endomorphism;

    protected ECPoint mappedPoint;

    public ECEndomorphism getEndomorphism()
    {
        return endomorphism;
    }

    public void setEndomorphism(ECEndomorphism endomorphism)
    {
        this.endomorphism = endomorphism;
    }

    public ECPoint getMappedPoint()
    {
        return mappedPoint;
    }

    public void setMappedPoint(ECPoint mappedPoint)
    {
        this.mappedPoint = mappedPoint;
    }
}
