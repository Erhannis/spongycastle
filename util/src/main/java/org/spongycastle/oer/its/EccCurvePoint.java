package org.spongycastle.oer.its;

import org.spongycastle.asn1.ASN1Object;

/**
 * Common interface for ITS curve points.
 */
public abstract class EccCurvePoint
    extends ASN1Object
{
    public abstract byte[] getEncodedPoint();
}
