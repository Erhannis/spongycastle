package org.spongycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.spongycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.spongycastle.bcpg.ECDHPublicBCPGKey;
import org.spongycastle.bcpg.MPInteger;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.Wrapper;
import org.spongycastle.crypto.agreement.ECDHBasicAgreement;
import org.spongycastle.crypto.agreement.X25519Agreement;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.generators.X25519KeyPairGenerator;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.params.X25519KeyGenerationParameters;
import org.spongycastle.crypto.params.X25519PublicKeyParameters;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.operator.PGPPad;
import org.spongycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.openpgp.operator.RFC6637Utils;
import org.spongycastle.util.BigIntegers;

/**
 * A method generator for supporting public key based encryption operations.
 */
public class BcPublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private static final byte X_HDR = 0x40;

    private SecureRandom random;
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter cryptoPublicKey = keyConverter.getPublicKey(pubKey);

            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket,
                    new BcKeyFingerprintCalculator());

                if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.init(ephKp.getPrivate());

                    byte[] secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(cryptoPublicKey, secret, 0);

                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
                    ephPubEncoding[0] = X_HDR;
                    ((X25519PublicKeyParameters)ephKp.getPublic()).encode(ephPubEncoding, 1);

                    return encryptSessionInfo(ecPubKey, sessionInfo, secret, userKeyingMaterial, ephPubEncoding);
                }
                else
                {
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).getParameters();

                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(ephKp.getPrivate());
                    BigInteger S = agreement.calculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);

                    byte[] ephPubEncoding = ((ECPublicKeyParameters)ephKp.getPublic()).getQ().getEncoded(false);

                    return encryptSessionInfo(ecPubKey, sessionInfo, secret, userKeyingMaterial, ephPubEncoding);
                }
            }
            else
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(pubKey.getAlgorithm());

                c.init(true, new ParametersWithRandom(cryptoPublicKey, random));

                return c.processBlock(sessionInfo, 0, sessionInfo.length);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
    }

    private byte[] encryptSessionInfo(ECDHPublicBCPGKey ecPubKey, byte[] sessionInfo, byte[] secret,
        byte[] userKeyingMaterial, byte[] ephPubEncoding) throws IOException, PGPException
    {
        RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
            new BcPGPDigestCalculatorProvider().get(ecPubKey.getHashAlgorithm()), ecPubKey.getSymmetricKeyAlgorithm());
        KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        Wrapper c = BcImplProvider.createWrapper(ecPubKey.getSymmetricKeyAlgorithm());
        c.init(true, new ParametersWithRandom(key, random));
        byte[] C = c.wrap(paddedSessionData, 0, paddedSessionData.length);

        byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).getEncoded();

        byte[] rv = new byte[VB.length + 1 + C.length];
        System.arraycopy(VB, 0, rv, 0, VB.length);
        rv[VB.length] = (byte)C.length;
        System.arraycopy(C, 0, rv, VB.length + 1, C.length);
        return rv;
    }
}
