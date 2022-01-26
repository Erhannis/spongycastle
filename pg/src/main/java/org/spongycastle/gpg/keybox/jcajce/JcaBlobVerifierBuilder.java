package org.spongycastle.gpg.keybox.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.spongycastle.jcajce.util.DefaultJcaJceHelper;
import org.spongycastle.jcajce.util.JcaJceHelper;
import org.spongycastle.jcajce.util.NamedJcaJceHelper;
import org.spongycastle.jcajce.util.ProviderJcaJceHelper;

public class JcaBlobVerifierBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    /**
     * Default constructor.
     */
    public JcaBlobVerifierBuilder()
    {
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param provider the JCA provider to use.
     * @return the current builder.
     */
    public JcaBlobVerifierBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param providerName the name of the JCA provider to use.
     * @return the current builder.
     */
    public JcaBlobVerifierBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcaBlobVerifier build()
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        return new JcaBlobVerifier(helper);
    }
}
