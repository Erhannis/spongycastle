package org.spongycastle.math.ec;

public interface PreCompCallback
{
    PreCompInfo precompute(PreCompInfo existing);
}
