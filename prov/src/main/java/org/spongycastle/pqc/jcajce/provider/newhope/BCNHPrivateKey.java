package org.spongycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.spongycastle.pqc.crypto.util.PrivateKeyFactory;
import org.spongycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.spongycastle.pqc.jcajce.interfaces.NHPrivateKey;
import org.spongycastle.util.Arrays;

public class BCNHPrivateKey
    implements NHPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient NHPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCNHPrivateKey(
        NHPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (NHPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this NH private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (!(o instanceof BCNHPrivateKey))
        {
            return false;
        }
        BCNHPrivateKey otherKey = (BCNHPrivateKey)o;

        return Arrays.areEqual(params.getSecData(), otherKey.params.getSecData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getSecData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public short[] getSecretData()
    {
        return params.getSecData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
