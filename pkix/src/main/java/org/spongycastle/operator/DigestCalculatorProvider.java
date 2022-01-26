package org.spongycastle.operator;

import org.spongycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The base interface for a provider of DigestCalculator implementations.
 */
public interface DigestCalculatorProvider
{
    DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException;
}
