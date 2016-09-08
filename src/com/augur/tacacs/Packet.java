package com.augur.tacacs;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

/**
 * Each TACACS+ packet has a standard header.  The body structure is variable. 
 * This class is abstract, implemented for specific packet types by subclasses: 
 * AcctReply, AcctRequest, AuthenContinue, AuthenStart, AuthenReply, 
 * AuthorRequest, and AuthorResponse.
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public abstract class Packet
{
	static final int FF = 0xFF;
	static final int FFFF = 0xFFFF;
	final Header header;
	
	
	Packet(Header header)
	{
		this.header = header;
	}
	
	
	/**
	 * @return A boolean indicating if this packet represents the last for this
	 * session; this base implementation returns 'false', but overriding classes
	 * may return 'true' based on the class and/or the status field in the packet's 
	 * body payload.
	 */
	boolean isEndOfSession() { return false; }
	
	/**
	 * Writes the whole packet.
	 * @param out  The destination OutputStream
	 * @param key The byte[] secret key shared between the client and server.
	 * @throws IOException if there is a problem writing to the given OutputStream.
	 */
	abstract void write(OutputStream out, byte[] key) throws IOException;

	/**
	 * Reads the next reply packet from the server.
	 * @param tacacs The TacacsReader providing I/O and session management
	 * @param key The secret key byte[] shared with the server
	 * @return A Packet subclass instance: AuthenReply, AcctReply, or AuthorReply
	 * @throws IOException 
	 */
	public static Packet readNext(TacacsReader tacacs, byte[] key) throws IOException
	{
		byte[] headerBytes = new byte[12];
//		System.out.println("Waiting to read a header...");
		tacacs.readFully(headerBytes);
		Header header = new Header(headerBytes); 
//		System.out.println("Got header="+header);
		byte[] body = new byte[header.bodyLength];
		tacacs.readFully(body); // read the body before potentially throwing any exceptions below, so that the input stream is left clean
		if (header.version==null) { throw new IOException("Received unknown packet header version code: "+((headerBytes[0]&0xf0)>>>4)+"."+(headerBytes[0]&0x0f)); }
		if (header.type==null) { throw new IOException("Received unknown packet header type code: "+headerBytes[1]); }
		byte[] bodyClear;
		try { bodyClear = header.toggleCipher(body, key); } catch (NoSuchAlgorithmException e) { throw new IOException(e.getMessage()); }
		if (tacacs instanceof TacacsServer)
		{
			//System.out.println("Reading as a TacacsServer");
			switch (header.type)
			{
				case AUTHEN: 
					Session s = tacacs.findSession(header.sessionID);
					if (s==null) // This is the only way to know the packet is AuthenStart and not AuthenContinue!   
					{ 
						AuthenStart p = new AuthenStart(header, bodyClear); 
						s = new SessionServer(p.authen_service, p.port, p.rem_addr, p.priv_lvl, tacacs, header.sessionID);
						tacacs.addSession(s);
						return p;
					}
					else { return new AuthenContinue(header, bodyClear); }
				case ACCT: 
						AcctRequest acp = new AcctRequest(header, bodyClear); 
						s = new SessionServer(acp.authen_service, acp.port, acp.rem_addr, acp.priv_lvl, tacacs, header.sessionID);
						tacacs.addSession(s);
						return acp;
				case AUTHOR: 
						AuthorRequest aup = new AuthorRequest(header, bodyClear); 
						s = new SessionServer(aup.authen_service, aup.port, aup.rem_addr, aup.priv_lvl, tacacs, header.sessionID);
						tacacs.addSession(s);
						return aup;
				default: throw new IOException("Server-side packet header type not supported: " + header.type); // shouldn't happen
			}
		}
		else // is client...
		{
			//System.out.println("Reading as a TacacsClient");
			switch (header.type)
			{
				case AUTHEN: return new AuthenReply(header, bodyClear);
				case ACCT: return new AcctReply(header, bodyClear);
				case AUTHOR: return new AuthorReply(header, bodyClear);
				default: throw new IOException("Client-side packet header type not supported: " + header.type); // shouldn't happen
			}
		}
	}

	
	/**
	 * Reads the next request packet from the client; THIS IS FOR USE ON A SERVER ONLY.
	 * @param din The DataInputStream
	 * @param key The secret key byte[] shared with the server
	 * @return A Packet subclass instance: AuthenReply, AcctReply, or AuthorReply
	 * @throws IOException 
	 */
	public static Packet readNextRequest(DataInputStream din, byte[] key) throws IOException
	{
		byte[] headerBytes = new byte[12];
		din.readFully(headerBytes);
		Header header = new Header(headerBytes); 
		byte[] body = new byte[header.bodyLength];
		din.readFully(body); // read the body before potentially throwing any exceptions below, so that the input stream is left clean
		if (header.version==null) { throw new IOException("Received unknown packet header version code: "+((headerBytes[0]&0xf0)>>>4)+"."+(headerBytes[0]&0x0f)); }
		if (header.type==null) { throw new IOException("Received unknown packet header type code: "+headerBytes[1]); }
		byte[] bodyClear;
		try { bodyClear = header.toggleCipher(body, key); } catch (NoSuchAlgorithmException e) { throw new IOException(e.getMessage()); }
		switch (header.type)
		{
			case AUTHEN: 
				if (header.seqNum==1) { return new AuthenStart(header, bodyClear); }
				else { return new AuthenContinue(header, bodyClear); }
			case ACCT: return new AcctRequest(header, bodyClear);
			case AUTHOR: return new AuthorRequest(header, bodyClear);
			default: throw new IOException("Server-side packet header type not supported: " + header.type); // shouldn't happen
		}
	}

	
	Header getHeader() { return header; }
	

	static int toInt(byte a, byte b)
	{
		return ((a&FF)<<8) | (b&FF);
	}

	static int toInt(byte a, byte b, byte c, byte d)
	{
		return ((a&FF)<<24) | (b&FF<<16) | ((c&FF)<<8) | (d&FF);
	}

	static String toHex(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder(bytes.length*2);
		for (byte b : bytes) 
		{ 
			if ((b&FF)<0xf) sb.append("0");
			sb.append(Integer.toHexString(b&FF));
		}
		return sb.toString();
	}
	
	static byte[] toBytes4(int i)
	{
		return new byte[] { (byte)((i>>>24)&FF), (byte)((i>>>16)&FF), (byte)((i>>>8)&FF), (byte)(i&FF) };
	}
	
	static byte[] toBytes2(int i)
	{
		return new byte[] { (byte)((i>>>8)&FF), (byte)(i&FF) };
	}
	
//	static byte[] lengthBytes2(byte[] bytes)
//	{
//		return toBytes2(bytes==null?0:bytes.length);
//	}
}
