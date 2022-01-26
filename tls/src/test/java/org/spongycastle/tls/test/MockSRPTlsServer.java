package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import org.spongycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.AlertLevel;
import org.spongycastle.tls.BasicTlsSRPIdentity;
import org.spongycastle.tls.ChannelBinding;
import org.spongycastle.tls.ProtocolName;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SRPTlsServer;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.SimulatedTlsSRPIdentityManager;
import org.spongycastle.tls.TlsCredentialedSigner;
import org.spongycastle.tls.TlsSRPIdentity;
import org.spongycastle.tls.TlsSRPIdentityManager;
import org.spongycastle.tls.TlsSRPLoginParameters;
import org.spongycastle.tls.crypto.SRP6Group;
import org.spongycastle.tls.crypto.SRP6StandardGroups;
import org.spongycastle.tls.crypto.TlsCrypto;
import org.spongycastle.tls.crypto.TlsSRPConfig;
import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Hex;

class MockSRPTlsServer
    extends SRPTlsServer
{
    static final SRP6Group TEST_GROUP = SRP6StandardGroups.rfc5054_1024;
    static final byte[] TEST_IDENTITY = Strings.toUTF8ByteArray("client");
    static final byte[] TEST_PASSWORD = Strings.toUTF8ByteArray("password");
    static final TlsSRPIdentity TEST_SRP_IDENTITY = new BasicTlsSRPIdentity(TEST_IDENTITY, TEST_PASSWORD);
    static final byte[] TEST_SALT = Strings.toUTF8ByteArray("salt");
    static final byte[] TEST_SEED_KEY = Strings.toUTF8ByteArray("seed_key");

    MockSRPTlsServer()
        throws IOException
    {
        super(new BcTlsCrypto(new SecureRandom()), new MyIdentityManager(new BcTlsCrypto(new SecureRandom())));
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        return protocolNames;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server raised alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-SRP server negotiated " + serverVersion);

        return serverVersion;
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
        }

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));

        byte[] srpIdentity = context.getSecurityParametersConnection().getSRPIdentity();
        if (srpIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(srpIdentity);
            System.out.println("TLS-SRP server completed handshake for SRP identity: " + name);
        }
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.dsa);
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.only();
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    static class MyIdentityManager
        implements TlsSRPIdentityManager
    {
        protected SimulatedTlsSRPIdentityManager unknownIdentityManager;

        MyIdentityManager(TlsCrypto crypto)
            throws IOException
        {
            unknownIdentityManager = SimulatedTlsSRPIdentityManager.getRFC5054Default(crypto, TEST_GROUP, TEST_SEED_KEY);
        }

        public TlsSRPLoginParameters getLoginParameters(byte[] identity)
        {
            if (Arrays.constantTimeAreEqual(TEST_IDENTITY, identity))
            {
                SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
                verifierGenerator.init(TEST_GROUP.getN(), TEST_GROUP.getG(), new SHA1Digest());

                BigInteger verifier = verifierGenerator.generateVerifier(TEST_SALT, identity, TEST_PASSWORD);

                TlsSRPConfig srpConfig = new TlsSRPConfig();
                srpConfig.setExplicitNG(new BigInteger[]{ TEST_GROUP.getN(), TEST_GROUP.getG() });

                return new TlsSRPLoginParameters(identity, srpConfig, verifier, TEST_SALT);
            }

            return unknownIdentityManager.getLoginParameters(identity);
        }
    }
}
