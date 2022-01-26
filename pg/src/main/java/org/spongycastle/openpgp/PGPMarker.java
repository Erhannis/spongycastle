/*
 * Created on Mar 6, 2004
 *
 * To change this generated comment go to 
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package org.spongycastle.openpgp;

import java.io.IOException;

import org.spongycastle.bcpg.BCPGInputStream;
import org.spongycastle.bcpg.MarkerPacket;
import org.spongycastle.bcpg.Packet;

/**
 * a PGP marker packet - in general these should be ignored other than where
 * the idea is to preserve the original input stream.
 */
public class PGPMarker
{
    private MarkerPacket p;
    
    /**
     * Default constructor.
     * 
     * @param in
     * @throws IOException
     */
    public PGPMarker(
        BCPGInputStream in) 
        throws IOException
    {
        Packet packet = in.readPacket();
        if (!(packet instanceof MarkerPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        p = (MarkerPacket)packet;
    }
}
