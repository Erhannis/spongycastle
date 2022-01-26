package org.spongycastle.its;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.oer.its.Certificate;
import org.spongycastle.oer.its.CertificateBase;
import org.spongycastle.oer.its.CertificateId;
import org.spongycastle.oer.its.CertificateType;
import org.spongycastle.oer.its.EccP256CurvePoint;
import org.spongycastle.oer.its.HashedId;
import org.spongycastle.oer.its.IssuerIdentifier;
import org.spongycastle.oer.its.PublicEncryptionKey;
import org.spongycastle.oer.its.ToBeSignedCertificate;
import org.spongycastle.oer.its.VerificationKeyIndicator;
import org.spongycastle.operator.DigestCalculator;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.util.Arrays;

public class ITSImplicitCertificateBuilder
    extends ITSCertificateBuilder
{
    private final IssuerIdentifier issuerIdentifier;

    public ITSImplicitCertificateBuilder(ITSCertificate issuer, DigestCalculatorProvider digestCalculatorProvider, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, tbsCertificate);
        // TODO is this always true?
        AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        ASN1ObjectIdentifier digestAlg = digestAlgId.getAlgorithm();
        DigestCalculator calculator;
        try
        {
            calculator = digestCalculatorProvider.get(digestAlgId);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }

        try
        {
            OutputStream os = calculator.getOutputStream();
            os.write(issuer.getEncoded());
            os.close();
        }
        catch (IOException ioex)
        {
            throw new IllegalStateException(ioex.getMessage(), ioex);
        }

        byte[] parentDigest = calculator.getDigest();

        IssuerIdentifier.Builder issuerIdentifierBuilder = IssuerIdentifier.builder();
        HashedId.HashedId8 hashedID = new HashedId.HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length));
        if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            issuerIdentifierBuilder.sha256AndDigest(hashedID);
        }
        else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            issuerIdentifierBuilder.sha384AndDigest(hashedID);
        }
        else
        {
            throw new IllegalStateException("unknown digest");
        }
        this.issuerIdentifier = issuerIdentifierBuilder.createIssuerIdentifier();
    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y)
    {
        return build(certificateId, x, y, null);
    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y, PublicEncryptionKey publicEncryptionKey)
    {
        EccP256CurvePoint reconstructionValue = EccP256CurvePoint.builder()
            .createUncompressedP256(x, y);

        ToBeSignedCertificate.Builder tbsBldr = new ToBeSignedCertificate.Builder(tbsCertificateBuilder);

        tbsBldr.setCertificateId(certificateId);

        if (publicEncryptionKey != null)
        {
            tbsBldr.setEncryptionKey(publicEncryptionKey);
        }

        tbsBldr.setVerificationKeyIndicator(VerificationKeyIndicator.builder()
            .reconstructionValue(reconstructionValue)
            .createVerificationKeyIndicator());


        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        baseBldr.setVersion(version);
        baseBldr.setType(CertificateType.Implicit);

        baseBldr.setIssuer(issuerIdentifier);

        baseBldr.setToBeSignedCertificate(tbsBldr.createToBeSignedCertificate());

        Certificate.Builder bldr = new Certificate.Builder();

        bldr.setCertificateBase(baseBldr.createCertificateBase());

        return new ITSCertificate(bldr.createCertificate());
    }
}
