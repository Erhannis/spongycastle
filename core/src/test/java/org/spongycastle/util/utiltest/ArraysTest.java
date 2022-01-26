package org.spongycastle.util.utiltest;

import junit.framework.TestCase;
import org.spongycastle.util.Arrays;

public class ArraysTest
    extends TestCase
{
    public void testConcatenate()
    {
        assertNull(Arrays.concatenate((byte[])null, (byte[])null));
        assertNull(Arrays.concatenate((int[])null, (int[])null));
    }
}
