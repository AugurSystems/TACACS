package com.augur.tacacs;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class AcctReply extends Packet
{

	final TAC_PLUS.ACCT.STATUS status;
	final String server_msg; // for display to user
	final String data; // for display to admin or console or log

	AcctReply(Header header, byte[] body) throws IOException
	{
		super(header);
		// Verify...
		final int overhead = 5;
		int msgLen = toInt(body[0],body[1]);
		int dataLen = toInt(body[2],body[3]);
		int chkLen = overhead+msgLen+dataLen;
		if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
		//
		server_msg = (msgLen>0) ? new String(body, overhead, msgLen, StandardCharsets.UTF_8) : null; 
		data = (dataLen>0) ? new String(body, 5+msgLen, dataLen, StandardCharsets.UTF_8) : null; 
		status = TAC_PLUS.ACCT.STATUS.forCode(body[4]);
		if (status == null) { throw new IOException("Received unknown TAC_PLUS_ACCT_STATUS code: "+body[0]); }
	}

	AcctReply(Header header, TAC_PLUS.ACCT.STATUS status, String server_msg, String data)
	{
		super(header);
		this.status = status;
		this.server_msg = server_msg;
		this.data = data;
	}
	
	
	@Override boolean isEndOfSession() { return true; }
	
	
	public boolean isOK() { return status == TAC_PLUS.ACCT.STATUS.SUCCESS; }
	
		
	@Override public String toString()
	{
		return getClass().getSimpleName()+":"+header+"[status:"+status+" server_msg:'"+server_msg+"' data:'"+data+"']";
	}
	

	/** 
	 * @return A String message from the server, intended for display to the user; 
	 * probably null if the accounting was successful.
	 */
	public String getServerMsg()
	{
		return server_msg;
	}


	/** 
	 * @return A String message from the server, intended for display to the admin usually via console or log; 
	 * probably null if the accounting was successful.
	 */
	public String getData()
	{
		return data;
	}
	
	
	/**
	 * Writes the whole packet.
	 * @param out  The destination OutputStream
	 * @param key The byte[] secret key shared between the client and server.
	 * @param md A shared MessageDigest; will be sync'd.
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
		body.write(toBytes2(smsgBytes==null?0:smsgBytes.length));
		body.write(toBytes2(dataBytes==null?0:dataBytes.length));
		body.write(status.code());
		if (smsgBytes!=null) { body.write(smsgBytes); }
		if (dataBytes!=null) { body.write(dataBytes); }
		byte[] bodyBytes = body.toByteArray();
		header.writePacket(out, bodyBytes, key);
	}
	

}
