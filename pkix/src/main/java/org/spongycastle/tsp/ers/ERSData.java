package org.spongycastle.tsp.ers;

import org.spongycastle.operator.DigestCalculator;

/**
 * General interface for an ERSData data group object.
 */
public interface ERSData
{
    /**
     * Return the calculated hash for the Data
     *
     * @param digestCalculator  digest calculator to use.
     * @return calculated hash.
     */
    byte[] getHash(DigestCalculator digestCalculator);
}
