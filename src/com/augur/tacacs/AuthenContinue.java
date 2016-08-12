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
public class AuthenContinue extends Packet
{

	final byte flags;
	final String user_msg;
	final String data;
	
	/**
	 * Constructor for when reading incoming packets.
	 */
	AuthenContinue(Header header, byte[] body) throws IOException
	{
		super(header);
		// Verify 
		int overhead = 3;
		if (body.length<overhead) { throw new IOException("Corrupt packet or bad key"); }
		int chkLen = overhead+body[0]+body[1];
		if (chkLen != body.length) { throw new IOException("Corrupt packet or bad key"); }
		//
		flags = body[4];
		int ulen = toInt(body[0],body[1]);
		user_msg = (ulen>0) ? new String(body, 5, ulen, StandardCharsets.UTF_8) : null; 
		int dlen = toInt(body[2],body[3]);
		data = (dlen>0) ? new String(body, 5+ulen, dlen, StandardCharsets.UTF_8) : null; 
	}

	
	/**
	 * Constructor for when building outgoing packets.  Note that there are 
	 * currently no uses of the 'data' field in CONTINUE packets.
	 */
	AuthenContinue(Header header, String user_msg, byte flags)
	{
		super(header);
		this.user_msg = user_msg;
		this.data = null; // no uses as of version 13.1
		this.flags = flags;
	}


	@Override public String toString()
	{
		return getClass().getSimpleName()+":"+header+"[flags:"+flags+" user_msg:'"+user_msg+"' data:'"+data+"']";
	}
	

	/**
	 * Writes the whole packet.
	 * @param out  The destination OutputStream
	 * @param key The byte[] secret key shared between the client and server.
	 * @throws IOException if there is a problem writing to the given OutputStream.
	 */
	@Override void write(OutputStream out, byte[] key) throws IOException
	{
		byte[] umsgBytes = user_msg==null?null:user_msg.getBytes(StandardCharsets.UTF_8);
		byte[] dataBytes = data==null?null:data.getBytes(StandardCharsets.UTF_8);
		// Truncating to fit packet...  lengths are limited to 16 bits
		if (umsgBytes!=null && umsgBytes.length>FFFF) { umsgBytes = Arrays.copyOfRange(umsgBytes,0,FFFF); }
		if (dataBytes!=null && dataBytes.length>FFFF) { dataBytes = Arrays.copyOfRange(dataBytes,0,FFFF); }
		ByteArrayOutputStream body = new ByteArrayOutputStream(3 + (umsgBytes==null?0:umsgBytes.length) + (dataBytes==null?0:dataBytes.length));
		body.write(toBytes2(umsgBytes==null?0:umsgBytes.length));
		body.write(toBytes2(dataBytes==null?0:dataBytes.length));
		body.write(flags);
		if (umsgBytes!=null) { body.write(umsgBytes); }
		if (dataBytes!=null) { body.write(dataBytes); }
		byte[] bodyBytes = body.toByteArray();
		header.writePacket(out, bodyBytes, key);
	}
	
}
