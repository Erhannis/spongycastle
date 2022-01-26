#
# JDK 1.2 edits

ed org/spongycastle/gpg/SExpression.java <<%
g/\.\.\. /s//[]/g
w
q
%


ed org/spongycastle/asn1/ASN1Integer.java <<%
g/private final byte.. bytes;/s/final//
w
q
%


(
cd  org/spongycastle/asn1/; 
for i in *.java
do
ed $i <<%%
g/final .* contents/s/final//
g/final .* start/s/final//
w
q
%%
done
)

ed org/spongycastle/asn1/ASN1TaggedObject.java <<%
g/final .* explicitness;/s/final//
g/final .* obj;/s/final//
g/final .* tagClass;/s/final//
g/final .* tagNo;/s/final//
w
q
%

ed org/spongycastle/asn1/ASN1ObjectIdentifier.java <<%
g/private final String identifier;/s/final//
w
q
%

ed org/spongycastle/asn1/DERBitString.java <<%
g/protected final byte...*data;/s/final//
g/protected final int.*padBits;/s/final//
g/final .* elements;/s/final//
g/final .* segmentLimit;/s/final//
w
q
%

ed org/spongycastle/asn1/BERBitString.java <<%
g/protected final byte...*data;/s/final//
g/protected final int.*padBits;/s/final//
g/final .* elements;/s/final//
g/final .* segmentLimit;/s/final//
w
q
%

ed org/spongycastle/asn1/BEROctetString.java <<%
g/private final ASN1OctetString/s/final//
g/private final int/s/final//
w
q
%

ed org/spongycastle/asn1/DERIA5String.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/spongycastle/asn1/DERNumericString.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/spongycastle/asn1/DERPrintableString.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/spongycastle/asn1/DERT61String.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/spongycastle/asn1/crmf/DhSigStatic.java <<%
g/private final /s/final//
w
q
%

ed org/spongycastle/asn1/tsp/ArchiveTimeStamp.java <<%
g/private final /s/final//
w
q
%

ed org/spongycastle/asn1/tsp/PartialHashtree.java <<%
g/private final /s/final//
w
q
%

ed org/spongycastle/asn1/pkcs/PBKDF2Params.java <<%
g/private final ASN1OctetString octStr;/s/final//
g/private final ASN1Integer iterationCount;/s/final//
g/private final ASN1Integer keyLength;/s/final//
g/private final AlgorithmIdentifier prf;/s/final//
w
q
%

ed org/spongycastle/asn1/x9/X9ECPoint.java <<%
g/private final ASN1OctetString encoding;/s/final//
w
q
%

ed org/spongycastle/asn1/x500/style/BCStyle.java <<%
g/protected final .*defaultLookUp;/s/final//
g/protected final .*defaultSymbols;/s/final//
w
q
%

ed org/spongycastle/asn1/x500/style/RFC4519Style.java <<%
g/protected final .*defaultLookUp;/s/final//
g/protected final .*defaultSymbols;/s/final//
w
q
%

ed org/spongycastle/crypto/agreement/kdf/GSKKDFParameters.java <<%
g/private final /s/final//
w
q
%

ed org/spongycastle/crypto/signers/Ed448Signer.java <<%
g/private final/s/final//
w
q
%

ed org/spongycastle/crypto/signers/Ed25519ctxSigner.java <<%
g/private final/s/final//
w
q
%

ed org/spongycastle/crypto/signers/SM2Signer.java <<%
g/private final/s/final//
w
q
%

ed org/spongycastle/crypto/signers/ISOTrailers.java <<%
g/private static final Map.* trailerMap;/s/final//
w
q
%

ed org/spongycastle/jcajce/PKCS12Key.java <<%
g/private final char.* password;/s/final//
g/private final boolean.* useWrongZeroLengthConversion;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/FPEParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/MQVParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/KTSParameterSpec.java <<%
g/private final .*algorithmName;/s/final//
w
q
%

ed org/spongycastle/operator/jcajce/JceKTSKeyWrapper.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/cms/CMSTypedStream.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/cms/SignerInformation.java <<%
g/private final .*;/s/final//
g/protected final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/its/CertificateType.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/ASN1InputStream.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/ASN1StreamParser.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/dvcs/DVCSTime.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/x509/UserNotice.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/BodyPartID.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/CMCFailInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/CMCStatus.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/CMCStatusInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/OtherStatusInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cmc/TaggedRequest.java <<%
g/private final .*;/s/final//
w
q
%

for i in mceliece/McElieceCCA2Parameters.java sphincs/HashFunctions.java 
do
ed org/spongycastle/pqc/crypto/$i <<%
g/private final .*;/s/final//
w
q
%
done

ed org/spongycastle/cert/dane/TruncatingDigestCalculator.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/crypto/signers/RSADigestSigner.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/crypto/agreement/SM2KeyExchange.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/crypto/engines/SM2Engine.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/bc/ObjectStoreIntegrityCheck.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/AEADParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/asymmetric/dh/IESCipher.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/keystore/bcfks/BcFKSKeyStoreSpi.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/cert/dane/DANEEntry.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cryptopro/Gost2814789KeyWrapParameters.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/cryptopro/Gost2814789EncryptedKey.java <<%
g/private final .*;/s/final//
w
q
%

ed org/spongycastle/asn1/misc/ScryptParams.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/asn1/bc/LinkedCertificate.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/modes/G3413CFBBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/modes/G3413CTRBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/modes/KGCMBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/DHUParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/DHDomainParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/GOST3410ParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/params/ECGOST3410Parameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/params/FPEParameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/test/SP80038GTest.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/util/JournalingSecureRandom.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/util/Fingerprint.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/openpgp/operator/jcajce/JcaPGPContentSignerBuilder.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/openpgp/operator/jcajce/JcaKeyFingerprintCalculator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/asn1/ASN1Integer.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/asymmetric/x509/PEMUtil <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/generators/Argon2BytesGenerator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/generators/OpenSSLPBEParametersGenerator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/macs/Zuc128Mac.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/macs/Zuc256Mac.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/params/ECDomainParameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/asymmetric/x509/PEMUtil.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jce/provider/test/ZucTest.java <<%
g/private.*final.*;/s/final//
g/(final /s/final//
w
q
%

ed org/spongycastle/bcpg/SignatureSubpacketInputStream.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/provider/symmetric/util/BCPBEKey.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/pkix/PKIXIdentity.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/pkix/jcajce/JcaPKIXIdentity.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/jcajce/spec/CompositeAlgorithmSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/digests/ParallelHash.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/spongycastle/crypto/digests/TupleHash.java <<%
g/private.*final.*;/s/final//
w
q
%

