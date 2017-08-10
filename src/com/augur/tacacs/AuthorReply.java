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
public class AuthorReply extends Packet
{
	final TAC_PLUS.AUTHOR.STATUS status;
	final String server_msg; // optional message for user
	final String data; // admin or console log; not for user
	final Argument[] arguments;
	
	@Override public String toString()
	{
		StringBuilder sb = new StringBuilder(100);
		sb.append(getClass().getSimpleName()).append(":").append(header);
		sb.append("[");
		sb.append("status:").append(status);
		sb.append(" server_msg:'").append(server_msg).append("'");
		sb.append(" data:'").append(data).append("'");
		sb.append(" arguments:[").append(Arrays.toString(arguments));
		sb.append("]]");
		return sb.toString();
	}
	

	AuthorReply(Header header, TAC_PLUS.AUTHOR.STATUS status, String server_msg, String data, Argument[] arguments)
	{
		super(header);
		this.status = status;
		this.server_msg = server_msg;
		this.data = data;
		this.arguments = arguments==null?new Argument[0]:arguments;
	}
	
	AuthorReply(Header header, byte[] body) throws IOException
	{
		super(header);
			// Verify...
		int overhead = 6;
		if (body.length<overhead) { throw new IOException("Corrupt packet or bad key"); }
		int msgLen = toInt(body[2],body[3]);
		int dataLen = toInt(body[4],body[5]);
		int arg_cnt = body[1] & FF;
		int chkLen = overhead + arg_cnt + msgLen + dataLen;
		for (int i=0; i<arg_cnt; i++) { chkLen += body[overhead+i] & FF; }
		if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
		//
		status = TAC_PLUS.AUTHOR.STATUS.forCode(body[0]);
		arguments = new Argument[arg_cnt];
		int argOffset = 6 + arg_cnt + msgLen + dataLen;
		for (int i=0; i<arg_cnt; i++)
		{
			int argLen = body[6+i] & FF ;
			arguments[i] = new Argument(new String(Arrays.copyOfRange(body, argOffset, argOffset+argLen),StandardCharsets.UTF_8));
			argOffset += argLen;
		}
		if (status == null) { throw new IOException("Received unknown TAC_PLUS_AUTHOR_STATUS code: "+body[0]); }
		server_msg = (msgLen>0) ? new String(body, 6, msgLen, StandardCharsets.UTF_8) : null; 
		data = (dataLen>0) ? new String(body, 6+msgLen, dataLen, StandardCharsets.UTF_8) : null; 
	}

	
	@Override boolean isEndOfSession() { return true; }

	public boolean isOK() { return status==TAC_PLUS.AUTHOR.STATUS.PASS_ADD || status==TAC_PLUS.AUTHOR.STATUS.PASS_REPL; }

	/**
	 * Writes the whole packet.
	 * @param out  The destination OutputStream
	 * @param key The byte[] secret key shared between the client and server.
	 * @throws IOException if there is a problem writing to the given OutputStream.
	 */
	@Override void write(OutputStream out, byte[] key) throws IOException
	{
		byte[] smsgBytes = server_msg.getBytes(StandardCharsets.UTF_8);
		byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
		// Truncating to fit packet...  lengths are limited to 16 bytes
		if (smsgBytes!=null && smsgBytes.length>FFFF) { smsgBytes = Arrays.copyOfRange(smsgBytes,0,FFFF); }
		if (dataBytes!=null && dataBytes.length>FFFF) { dataBytes = Arrays.copyOfRange(dataBytes,0,FFFF); }
		// Truncating the number of arguments, and the length of the byte[] representations... limited to a byte
		byte[][] argsBytes = new byte[Math.min(FF,arguments.length)][];
		for (int i=0; i<argsBytes.length; i++) 
		{
			argsBytes[i] = arguments[i].toString().getBytes(StandardCharsets.UTF_8);
			if (argsBytes[i].length>FF) { argsBytes[i] = Arrays.copyOfRange(argsBytes[i],0,FF); }
		}
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.write(status.code());
		body.write(arguments.length);
		body.write(toBytes2(smsgBytes==null?0:smsgBytes.length));
		body.write(toBytes2(dataBytes==null?0:dataBytes.length));
		for (byte[] aBytes : argsBytes) { body.write(aBytes.length); }
		body.write(smsgBytes);
		body.write(dataBytes);
		for (byte[] aBytes : argsBytes) { body.write(aBytes); }
		header.writePacket(out, body.toByteArray(), key);
	}

	
	/** 
	 * @return A String message from the server, intended for display to the user; 
	 * probably null if the authorization was successful.
	 */
	public String getServerMsg()
	{
		return server_msg;
	}


	/** 
	 * @return A String message from the server, intended for display to the admin usually via console or log; 
	 * probably null if the authorization was successful.
	 */
	public String getData()
	{
		return data;
	}
	

	/** 
	 * @return The Argument[] returned from the server.  
	 * This is the object reference; editing the array is probably a bad idea.
	 */
	public Argument[] getArguments()
	{
		return arguments;
	}
	
	public String getValue(String attribute)
	{
		for (Argument a : arguments)
		{
			if (a.attribute.equals(attribute)) return a.value;
		}
		return null;
	}
	
	
}
