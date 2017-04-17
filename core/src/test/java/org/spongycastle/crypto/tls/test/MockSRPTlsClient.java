package org.spongycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;

import org.spongycastle.asn1.x509.Certificate;
import org.spongycastle.crypto.tls.AlertDescription;
import org.spongycastle.crypto.tls.AlertLevel;
import org.spongycastle.crypto.tls.CipherSuite;
import org.spongycastle.crypto.tls.ProtocolVersion;
import org.spongycastle.crypto.tls.SRPTlsClient;
import org.spongycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.spongycastle.crypto.tls.TlsAuthentication;
import org.spongycastle.crypto.tls.TlsExtensionsUtils;
import org.spongycastle.crypto.tls.TlsSession;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

class MockSRPTlsClient
    extends SRPTlsClient
{
    TlsSession session;

    MockSRPTlsClient(TlsSession session, byte[] identity, byte[] password)
    {
        super(identity, password);

        this.session = session;
    }

    public TlsSession getSessionToResume()
    {
        return this.session;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP client raised alert: " + AlertLevel.getText(alertLevel) + ", "
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
        out.println("TLS-SRP client received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        TlsSession newSession = context.getResumableSession();
        if (newSession != null)
        {
            byte[] newSessionID = newSession.getSessionID();
            String hex = Hex.toHexString(newSessionID);

            if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
            {
                System.out.println("Resumed session: " + hex);
            }
            else
            {
                System.out.println("Established session: " + hex);
            }

            this.session = newSession;
        }
    }

    public ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public Hashtable getClientExtensions() throws IOException
    {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
        return clientExtensions;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        System.out.println("TLS-SRP client negotiated " + serverVersion);
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new ServerOnlyTlsAuthentication()
        {
            public void notifyServerCertificate(org.spongycastle.crypto.tls.Certificate serverCertificate)
                throws IOException
            {
                Certificate[] chain = serverCertificate.getCertificateList();
                System.out.println("TLS-SRP client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    Certificate entry = chain[i];
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
                }
            }
        };
    }
}
