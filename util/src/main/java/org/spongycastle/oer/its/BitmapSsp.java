package org.spongycastle.oer.its;

import java.io.IOException;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DEROctetString;

public class BitmapSsp
    extends DEROctetString
{
    public BitmapSsp(byte[] string)
    {
        super(string);
    }

    public BitmapSsp(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }
}
