#
# JDK 1.2 edits

ed org.spongycastle.crypto/util/DERMacData.java <<%
g/private final String enc;/s/final//
g/private final int ordinal;/s/final//
g/private final byte.. macData;/s/final//
g/private final DERSequence sequence;/s/final//
w
q
%

ed org.spongycastle.crypto/util/DEROtherInfo.java <<%
g/private final DERSequence sequence;/s/final//
w
q
%

ed org.spongycastle.jcajce/spec/KTSParameterSpec.java <<%
g/private final String wrappingKeyAlgorithm;/s/final//
g/private final int keySizeInBits;/s/final//
g/private final AlgorithmParameterSpec parameterSpec;/s/final//
g/private final AlgorithmIdentifier kdfAlgorithm;/s/final//
w
q
%

ed org.spongycastle.util/test/FixedSecureRandom.java <<%
g/private static final boolean/s/final//
w
q
%

ed org.spongycastle.asn1/cmc/CertificationRequest.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.crypto/util/PBKDF2Config.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.crypto/util/ScryptConfig.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.pqc/crypto/newhope/NHOtherInfoGenerator.java <<%
g/private final/s/final//
g/protected final/s/final//
g/(getPublicKey(/s//(NHOtherInfoGenerator.getPublicKey(/
g/return getEncod/s//return NHOtherInfoGenerator.getEncod/
w
q
%

ed org.spongycastle.crypto/CryptoServicesRegistrar.java <<%
g/private final String/s/final//
g/private final Class/s/final//
w
q
%

ed org.spongycastle.crypto/params/Argon2Parameters.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.cert/crmf/bc/BcCRMFEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.crypto/modes/ChaCha20Poly1305.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.jcajce/provider/drbg/DRBG.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.cms/bc/BcCMSContentEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.crypto/prng/SP800SecureRandomBuilder.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.crypto/modes/GCMSIVBlockCipher.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.cms/CMSSignedDataGenerator.java <<%
g/LinkedHashSet/s//HashSet/g
w
q
%

ed org.spongycastle.cms/CMSAuthEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.cms/CMSAuthenticatedDataStreamGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.cms/CMSAuthenticatedDataGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.cms/CMSEnvelopedDataStreamGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.cms/CMSEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.cms/CMSEncryptedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org.spongycastle.openpgp/PGPExtendedKeyAttribute.java <<%
g/private final/s/final//
w
q
%

ed org.spongycastle.gpg/SExpression.java <<%
g/\.\.\. /s//[]/g
w
q
%

ed org.spongycastle.openpgp/operator/jcajce/JcePublicKeyDataDecryptorFactoryBuilder.java <<%
g/RSAKey/s//RSAPrivateKey/g
w
q
%

ed org.spongycastle.openpgp/PGPCanonicalizedDataGenerator.java <<%
g/FileNotFoundException/s//IOException/
w
q
%
