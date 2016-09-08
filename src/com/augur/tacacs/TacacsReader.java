package com.augur.tacacs;

import java.net.Socket;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

/**
 * This is used by both TACACS+ client and server for reading incoming packet.
 * <p>
 * The TACACS+ Protocol (version 1.78) is defined at 
 * <a href='https://tools.ietf.org/html/draft-grant-tacacs-02'>IETF.org</a>.
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */

public class TacacsReader extends Thread
{
	public static final int PORT_TACACS = 49;
	public static final boolean DEBUG = false;

	private final List<Session> sessions;
	private final byte[] key;
	private volatile boolean runnable;
	private final Socket socket;
	private final DataInputStream din;
	private final OutputStream out;

	
	protected TacacsReader(Socket socket, String key) throws IOException
	{
		super("TACACS+");
		setDaemon(true);
		this.key = key.getBytes(StandardCharsets.UTF_8);
		this.runnable = true;
		this.sessions = new ArrayList<>();
		this.socket = socket;
		din = new DataInputStream(socket.getInputStream());
		out = socket.getOutputStream();
	}

	
	public void shutdown()
	{
		if (runnable)
		{
			runnable = false;
			if (socket!=null) 
			{ 
				try { socket.close(); } 
				catch(IOException ioe) { } 
			}
		}
	}
	
	/** 
	 * @return A boolean indicating if this connection can be reused 
	 * to create new sessions.  (Some servers may not support socket reuse, and so  
	 * you will need a new TracacsClient for subsequent communications.) 
	 */
	public boolean isShutdown() 
	{ 
		return !runnable; 
	}
	
	protected final void addSession(Session s)
	{
		synchronized(sessions) { sessions.add(s); }  
	}
	
	/** Reads packets from server and dispatches them to sessions for handling. */
	@Override public void run()
	{
		IOException error = null;
		while(runnable)
		{
			try 
			{
				Packet p = Packet.readNext(this, key); 
				synchronized(sessions)
				{
					Session s = findSession(p.header.sessionID);
					if (s!=null) 
					{ 
						s.handlePacket(p);
						if (s.isEnd()) 
						{
							sessions.remove(s); 
							if (!s.isSingleConnectMode()) 
							{
								error = new IOException("Not in 'single connect mode'.");
								shutdown();
							}
						}
					}
					else if (DEBUG) { System.out.println("TACACS+> Couldn't find session for: "+p); }
				}
			}
			catch (IOException e)
			{
				error = e;
				shutdown();
			}
		}
		if (error==null) { error = new IOException("Shutdown"); }
		synchronized(sessions)
		{
			for (Session s : sessions) { s.end(error); }
			sessions.clear();
		}
	}
	
	
	Session findSession(byte[] id)
	{
		synchronized(sessions)
		{
			for (Session s: sessions) { if (s.isID(id)) return s; }
			return null;
		}
	}
	
	
	public void readFully(byte[] bytes) throws IOException
	{
		din.readFully(bytes);
	}
	
	
	public void write(Packet p) throws IOException
	{
		synchronized(out)
		{
			try 
			{ 
				p.write(out, key); 
				if (DEBUG) { System.out.println("Transmit --> "+p); }
			}
			catch(IOException e)
			{
				shutdown();// try { socket.close(); } catch (IOException io) { }
				throw e;
			}
		}
	}
	
	
}
