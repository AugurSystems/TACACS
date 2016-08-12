package com.augur.tacacs;

import java.net.Socket;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * This is the base for a TACACS+ client or server, including packet I/O.
 * For usage of this library, see TacacsClient or TacacsServer classes.
 * <p>
 * The TACACS+ Protocol (version 1.78) is defined at 
 * <a href='https://tools.ietf.org/html/draft-grant-tacacs-02'>IETF.org</a>.
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */

public class Tacacs extends Thread
{
  public static final int PORT_TACACS = 49;
	public static final boolean DEBUG = false;

	private final List<Session> sessions;
  private final byte[] key;
	private volatile boolean runnable;
	private final Socket socket;
	private final DataInputStream din;
	private final OutputStream out;

	
	protected Tacacs(Socket socket, String key) throws IOException
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
		Thread.dumpStack();
		runnable = false;
		if (socket!=null) { try { socket.close(); } catch(IOException ioe) { } }
	}
	
	/** 
	 * @return A boolean indicating if this connection can be reused 
	 * to create new sessions.  (Some servers may not support socket reuse, and so  
	 * you will need a new TracacsClient for subsequent communications.) 
	 */
	public boolean isShutdown() { return runnable && super.isAlive(); }
	
	protected final void addSession(Session s)
	{
		synchronized(sessions) { sessions.add(s); }  
	}
	
	/** Reads packets from server and dispatches them to sessions for handling. */
	@Override	public void run()
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
								runnable = false;
								try { socket.close(); } catch (IOException io) { }
								error = new IOException("Other side does not support 'single connect mode'.");
							}
						}
					}
					else if (DEBUG) { System.out.println("TACACS+> Couldn't find session for: "+p); }
				}
			}
			catch (IOException e)
			{
				error = e;
				runnable = false;
				try { socket.close(); } catch (IOException io) { }
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
				try { socket.close(); } catch (IOException io) { }
				throw e;
			}
		}
	}
	
	
}
