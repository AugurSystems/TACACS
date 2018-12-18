package com.augur.tacacs;
import java.io.IOException;

/**
 * An interface to abstract I/O methods implemented by TacacsClient and TacacsServer.
 * Used by SessionClient and SessionServer to write packets to the stream, which
 * might be shared by several concurrent sessions, so must be owned and synchronized
 * by the parent TacacsClient or TacacsServer objects.
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public interface IO
{
	/** Writes a packet to the I/O stream. */
	public void write(Packet p) throws IOException;
	
	public void readFully(byte[] bytes) throws IOException;
}
