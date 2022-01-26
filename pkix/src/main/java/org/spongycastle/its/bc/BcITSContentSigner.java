package org.spongycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.sec.SECObjectIdentifiers;
import org.spongycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.io.DigestOutputStream;
import org.spongycastle.crypto.params.ECNamedDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.signers.DSADigestSigner;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.its.ITSCertificate;
import org.spongycastle.its.operator.ITSContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcDefaultDigestProvider;
import org.spongycastle.util.Arrays;

public class BcITSContentSigner
    implements ITSContentSigner
{
    private final ECPrivateKeyParameters privKey;
    private final ITSCertificate signerCert;
    private final AlgorithmIdentifier digestAlgo;
    private final Digest digest;
    private final byte[] parentData;
    private final ASN1ObjectIdentifier curveID;
    private final byte[] parentDigest;

    /**
     * Constructor for self-signing.
     *
     * @param privKey
     */
    public BcITSContentSigner(ECPrivateKeyParameters privKey)
    {
        this(privKey, null);
    }

    public BcITSContentSigner(ECPrivateKeyParameters privKey, ITSCertificate signerCert)
    {
        this.privKey = privKey;
        this.curveID = ((ECNamedDomainParameters)privKey.getParameters()).getName();
        this.signerCert = signerCert;
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        try
        {
            this.digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm());
        }

        if (signerCert != null)
        {
            try
            {
                this.parentData = signerCert.getEncoded();
                this.parentDigest = new byte[digest.getDigestSize()];

                digest.update(parentData, 0, parentData.length);

                digest.doFinal(parentDigest, 0);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
            }
        }
        else
        {
            // self signed so we use a null digest for the parent.
            this.parentData = null;
            this.parentDigest = new byte[digest.getDigestSize()];
            digest.doFinal(parentDigest, 0);
        }
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return signerCert;
    }

    public byte[] getAssociatedCertificateDigest()
    {
        return Arrays.clone(parentDigest);
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public OutputStream getOutputStream()
    {
        return new DigestOutputStream(digest);
    }

    public boolean isForSelfSigning()
    {
        return parentData == null;
    }

    public byte[] getSignature()
    {
        byte[] clientCertDigest = new byte[digest.getDigestSize()];


        digest.doFinal(clientCertDigest, 0);

        final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(), digest);

        signer.init(true, privKey);

        signer.update(clientCertDigest, 0, clientCertDigest.length);

        signer.update(parentDigest, 0, parentDigest.length);

        return signer.generateSignature();
    }
}
