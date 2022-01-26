package org.spongycastle.pqc.jcajce.interfaces;

import org.spongycastle.pqc.jcajce.spec.QTESLAParameterSpec;

/**
 * Base interface for a qTESLA key.
 */
public interface QTESLAKey
{
    /**
     * Return the parameters for this key - in this case the security category.
     *
     * @return a QTESLAParameterSpec
     */
    QTESLAParameterSpec getParams();
}
