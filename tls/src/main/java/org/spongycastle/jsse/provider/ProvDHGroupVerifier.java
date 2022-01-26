package org.spongycastle.jsse.provider;

import org.spongycastle.tls.DefaultTlsDHGroupVerifier;
import org.spongycastle.tls.crypto.DHGroup;

class ProvDHGroupVerifier
    extends DefaultTlsDHGroupVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.spongycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.spongycastle.jsse.client.dh.unrestrictedGroups", false);

    ProvDHGroupVerifier()
    {
        super(provMinimumPrimeBits);
    }

    @Override
    protected boolean checkGroup(DHGroup dhGroup)
    {
        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
