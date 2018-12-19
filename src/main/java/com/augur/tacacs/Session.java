package com.augur.tacacs;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.TimeoutException;

/**
 * In TACACS+ parlance, a "session" is the client/server exchange of packets for 
 * one authentication, authorization, or accounting exchange.  Most sessions 
 * will consist of two packets: a request from the client, and a reply from the server.
 * ASCII-type authentications usually use a few more packets as the server prompts
 * for the client username, password, and other information (e.g. a user's
 * response to a previously configured "secret question", such as the name of 
 * their first pet).
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public abstract class Session
{
	static final byte FLAG_ZERO = (byte)0x0;
	final TacacsReader tacacs;
	
	/* Common fields for all actions; provided in client's first packet */
	protected String rem_addr;
	protected String port;
	protected byte priv_lvl;
	protected TAC_PLUS.AUTHEN.SVC authen_svc;
	protected byte[] id;
	protected Packet result = null;
	
	private Thread waitingThread = null;
	private IOException ioe = null;
	private Packet firstPacket = null;
		
	
	/**
	 * 
	 * @param authen_svc
	 * @param port
	 * @param rem_addr
	 * @param priv_lvl
	 * @param timeToLive
	 * @param tacacs
	 * @param id A four-byte session ID byte[]; if null, a new ID will be generated (needed for a new client session).
	 */
	Session(TAC_PLUS.AUTHEN.SVC authen_svc, String port, String rem_addr, byte priv_lvl, TacacsReader tacacs, byte[] id)
	{
		this.tacacs = tacacs;
		this.rem_addr = rem_addr;
		this.port = port;
		this.priv_lvl = priv_lvl;
		this.authen_svc = authen_svc;
		this.id = id==null? generateRandomBytes(4): id;
	}
	
	
	void handlePacket(Packet p) throws IOException {
		if (firstPacket==null) firstPacket = p;
	}
	
	/** 
	 * Determines if this session supports single connect mode.
	 * Overridden by SessionClient to implement 'singleConnect' config option, to
	 * ignore server's ability to reuse socket.
	 * 
	 * @return A boolean indicating if the first packet received during this session had the SINGLE_CONNECT flag set 
	 * @see TACACS+ specification, section 3.3 "Single Connect Mode" 
	 */
	boolean isSingleConnectMode() 
	{ 
		return firstPacket!=null && firstPacket.header.hasFlag(TAC_PLUS.PACKET.FLAG.SINGLE_CONNECT); 
	}
	
	
	protected synchronized void end(Packet result)
	{
		this.result = result;
		if (!isSingleConnectMode()) { tacacs.shutdown(); } // isSingleConnectMode() is overriden by SessionClient
		notifyAll();
	}

	synchronized void end(IOException endReason)
	{
		result = null;
		this.ioe = endReason;
		tacacs.shutdown();
		if (waitingThread!=null) waitingThread.interrupt();
	}
	
	boolean isEnd() { return ioe!=null || result!=null; }
	
	
	final boolean isID(byte[] id)
	{
		if (id.length != this.id.length) return false;
		for (int i=0; i<id.length; i++) { if (id[i] != this.id[i]) { return false; } }
		return true;
	}
	

	protected final synchronized void waitForReply(int timeoutMillis) throws TimeoutException, IOException
	{
		waitingThread = Thread.currentThread();
		long now = System.currentTimeMillis();
		final long timeoutTime = now + timeoutMillis;
		while ((timeoutTime > now) && !isEnd()) 
		{ 
			try { wait(timeoutTime-now); } 
			catch (InterruptedException ie) { } // will be interrupted by end() 
			now = System.currentTimeMillis();
		}
		if (!isEnd()) throw new TimeoutException();
		else if (ioe != null) throw ioe;
	}
	

	protected final synchronized void waitForeverForReply() throws TimeoutException, IOException
	{
		waitingThread = Thread.currentThread();
		while (!isEnd()) 
		{ 
			try { wait(); } 
			catch (InterruptedException ie) { } // will be interrupted by end() 
		}
		if (!isEnd()) throw new TimeoutException();
		else if (ioe != null) throw ioe;
	}
	
	
	/** Generate a random byte[], e.g. a session ID for a new client-side session, or a CHAP challenge. */
	final static byte[] generateRandomBytes(int length)
	{
		// Use of SecureRandom per https://www.cigital.com/blog/proper-use-of-javas-securerandom/ 
		SecureRandom sr;
		try { sr = SecureRandom.getInstance("SHA1PRNG", "SUN"); }
		catch (NoSuchAlgorithmException | NoSuchProviderException e) { sr = new SecureRandom(); } 
		byte[] bytes = new byte[length];
		sr.nextBytes(bytes);
		return bytes;
	}

	
	
}
