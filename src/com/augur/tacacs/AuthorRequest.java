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
public class AuthorRequest extends Packet
{

	final TAC_PLUS.AUTHEN.METH authen_method;
	final byte priv_lvl;
	final TAC_PLUS.AUTHEN.TYPE authen_type;
	final TAC_PLUS.AUTHEN.SVC authen_service;
	final String user;
	final String port;
	final String rem_addr;
	final Argument[] arguments;
	
	@Override public String toString()
	{
		StringBuilder sb = new StringBuilder(100);
		sb.append(getClass().getSimpleName()).append(":").append(header);
		sb.append("[");
		sb.append("authen_method:").append(authen_method);
		sb.append(" priv_lvl:").append(priv_lvl);
		sb.append(" authen_type:").append(authen_type);
		sb.append(" authen_service:").append(authen_service);
		sb.append(" user:").append(user);
		sb.append(" port:").append(port);
		sb.append(" rem_addr:").append(rem_addr);
		sb.append(" arguments:[").append(Arrays.toString(arguments));
		sb.append("]]");
		return sb.toString();
	}
	
	
	/**
	 * Constructor for when reading incoming packets.
	 */
	AuthorRequest(Header header, byte[] body) throws IOException
	{
		super(header);
		// Verify...
		int overhead = 8;
		if (body.length<overhead) { throw new IOException("Corrupt packet or bad key"); }
		int chkLen = overhead + body[4] + body[5] + body[6] + body[7];
		if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
		//
		authen_method = TAC_PLUS.AUTHEN.METH.forCode(body[0]);
		priv_lvl = body[1];
		authen_type = TAC_PLUS.AUTHEN.TYPE.forCode(body[2]);
		authen_service = TAC_PLUS.AUTHEN.SVC.forCode(body[3]);
		int arg_cnt = body[7];
		int i, offset = 8 + arg_cnt;
		i=body[4];     user = (i>0) ? new String(body, offset, i, StandardCharsets.UTF_8) : null; offset+=i;
		i=body[5];     port = (i>0) ? new String(body, offset, i, StandardCharsets.UTF_8) : null; offset+=i;
		i=body[6]; rem_addr = (i>0) ? new String(body, offset, i, StandardCharsets.UTF_8) : null; offset+=i;
		arguments = new Argument[arg_cnt];
		for (int a=0; a<arg_cnt; a++) 
		{ 
			String arg = new String(body, offset, body[8+a], StandardCharsets.UTF_8);
			arguments[a] = new Argument(arg); 
			offset+=body[8+a]; 
		}
	}

	
	/**
	 * Constructor for when building outgoing packets.
	 */
	AuthorRequest
	(
		Header header, 
		TAC_PLUS.AUTHEN.METH authen_method,
		byte priv_lvl,
		TAC_PLUS.AUTHEN.TYPE authen_type,
		TAC_PLUS.AUTHEN.SVC authen_service,
		String user,
		String port,
		String rem_addr,
		Argument[] arguments
	)
	{
		super(header);
		this.authen_method = authen_method;
		this.priv_lvl = priv_lvl;
		this.authen_type = authen_type;
		this.authen_service = authen_service;
		this.user = user;
		this.port = port;
		this.rem_addr = rem_addr;
		this.arguments = arguments;
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
		byte[] userBytes = user.getBytes(StandardCharsets.UTF_8); 
		byte[] portBytes = port.getBytes(StandardCharsets.UTF_8);
		byte[] remaBytes = rem_addr.getBytes(StandardCharsets.UTF_8);
		// Truncating to fit packet...  lengths are limited to a byte
		if (userBytes!=null && userBytes.length>FF) { userBytes = Arrays.copyOfRange(userBytes,0,FF); }
		if (portBytes!=null && portBytes.length>FF) { portBytes = Arrays.copyOfRange(portBytes,0,FF); }
		if (remaBytes!=null && remaBytes.length>FF) { remaBytes = Arrays.copyOfRange(remaBytes,0,FF); }
		// Truncating the number of arguments, and the length of the byte[] representations... limited to a byte
		byte[][] argsBytes = new byte[Math.min(FF,arguments.length)][];
		for (int i=0; i<argsBytes.length; i++) 
		{
			argsBytes[i] = arguments[i].toString().getBytes(StandardCharsets.UTF_8);
			if (argsBytes[i].length>FF) { argsBytes[i] = Arrays.copyOfRange(argsBytes[i],0,FF); }
		}
		//
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		body.write(authen_method.code());
		body.write(priv_lvl);
		body.write(authen_type.code());
		body.write(authen_service.code());
		body.write(userBytes.length);
		body.write(portBytes.length);
		body.write(remaBytes.length);
		body.write(argsBytes.length);
		for (byte[] aBytes : argsBytes) { body.write(aBytes.length); }
		body.write(userBytes);
		body.write(portBytes);
		body.write(remaBytes);
		for (byte[] aBytes : argsBytes) { body.write(aBytes); }
		header.writePacket(out, body.toByteArray(), key);
	}
	
}
