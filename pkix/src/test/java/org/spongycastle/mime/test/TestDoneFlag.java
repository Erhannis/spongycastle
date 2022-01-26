package org.spongycastle.mime.test;

class TestDoneFlag
{
    private boolean done = false;

    void markDone()
    {
        done = true;
    }

    boolean isDone()
    {
        return done;
    }
}
