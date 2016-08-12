package com.augur.tacacs;
import static com.augur.tacacs.Packet.FFFF;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class AuthenReply extends Packet
{

	final TAC_PLUS.AUTHEN.STATUS status;
	final byte flags; // TAC_PLUS_REPLY_FLAG_NOECHO or nothing
	final String server_msg;
	final String data;

	AuthenReply(Header header, TAC_PLUS.AUTHEN.STATUS status, byte flags, String server_msg, String data)
	{
		super(header);
		this.status = status;
		this.flags = flags;
		this.server_msg = server_msg;
		this.data = data;
	}

	AuthenReply(Header header, byte[] body) throws IOException
	{
		super(header);
		// Verify...
		int overhead = 6;
		if (body.length<overhead) { throw new IOException("Corrupt packet or bad key"); }
		int msgLen = toInt(body[2],body[3]);
		int dataLen = toInt(body[4],body[5]);
		int chkLen = overhead + msgLen + dataLen;
		if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
		//
		status = TAC_PLUS.AUTHEN.STATUS.forCode(body[0]);
		if (status == null) { throw new IOException("Received unknown TAC_PLUS_AUTHEN_STATUS code: "+body[0]); }
		flags = body[1];
		server_msg = (msgLen>0) ? new String(body, 6, msgLen, StandardCharsets.UTF_8) : null; 
		data = (dataLen>0) ? new String(body, 6+msgLen, dataLen, StandardCharsets.UTF_8) : null; 
	}

	
	@Override public String toString()
	{
		return getClass().getSimpleName()+":"+header+"[status:"+status+" flags:"+flags+" server_msg:'"+server_msg+"' data:'"+data+"']";
	}
	
	
	@Override boolean isEndOfSession() 
	{ 
		switch(status)
		{
			case ERROR:
			case FAIL:
			case FOLLOW:
			case RESTART: // TODO: per spec, this indicates that the authen_type was not acceptable, but others might be... cycle thru options?
			case PASS:
				return true;
			case GETDATA:
			case GETPASS:
			case GETUSER:
			default:
				return false;
		}
	}
	
	public boolean isOK() { return status == TAC_PLUS.AUTHEN.STATUS.PASS; }
	

	/**
	 * Writes the whole packet.
	 * @param out  The destination OutputStream
	 * @param key The byte[] secret key shared between the client and server.
	 * @throws IOException if there is a problem writing to the given OutputStream.
	 */
	@Override void write(OutputStream out, byte[] key) throws IOException
	{
		byte[] smsgBytes = server_msg==null?null:server_msg.getBytes(StandardCharsets.UTF_8);
		byte[] dataBytes = data==null?null:data.getBytes(StandardCharsets.UTF_8);
		// Truncating to fit packet...  lengths are limited to a 16 bits
		if (smsgBytes!=null && smsgBytes.length>FFFF) { smsgBytes = Arrays.copyOfRange(smsgBytes,0,FFFF); }
		if (dataBytes!=null && dataBytes.length>FFFF) { dataBytes = Arrays.copyOfRange(dataBytes,0,FFFF); }
		ByteArrayOutputStream body = new ByteArrayOutputStream(6 + (smsgBytes==null?0:smsgBytes.length) + (dataBytes==null?0:dataBytes.length));
		body.write(status.code());
		body.write(flags);
		body.write(toBytes2(smsgBytes==null?0:smsgBytes.length));
		body.write(toBytes2(dataBytes==null?0:dataBytes.length));
		if (smsgBytes!=null) { body.write(smsgBytes); }
		if (dataBytes!=null) { body.write(dataBytes); }
		byte[] bodyBytes = body.toByteArray();
		header.writePacket(out, bodyBytes, key);
	}
	

	boolean hasFlag(TAC_PLUS.REPLY.FLAG flag)
	{
		return (flags & flag.code()) != 0;
	}


	/** 
	 * @return A String message from the server, intended for display to the user; 
	 * probably null if the authentication was successful.
	 */
	public String getServerMsg()
	{
		return server_msg;
	}


	/** 
	 * @return A String message from the server, intended for display to the admin usually via console or log; 
	 * probably null if the authentication was successful.
	 */
	public String getData()
	{
		return data;
	}
	
	
}
