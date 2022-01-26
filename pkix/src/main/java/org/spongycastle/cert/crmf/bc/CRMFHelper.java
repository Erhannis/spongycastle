package org.spongycastle.cert.crmf.bc;

import java.security.SecureRandom;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.cert.crmf.CRMFException;
import org.spongycastle.crypto.CipherKeyGenerator;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.util.AlgorithmIdentifierFactory;
import org.spongycastle.crypto.util.CipherFactory;
import org.spongycastle.crypto.util.CipherKeyGeneratorFactory;

class CRMFHelper
{
    CRMFHelper()
    {
    }

    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CRMFException
    {
        try
        {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }
}
