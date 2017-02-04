package com.augur.tacacs;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import static com.augur.tacacs.Packet.toInt;

/**
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class Header
{
	static final int FF = 0xFF;

	/** Unique serial number within a session; must reset session if wrap. */
	final byte seqNum;

	final byte flags;

	final TAC_PLUS.PACKET.VERSION version;
	
	final TAC_PLUS.PACKET.TYPE type;
		
	/** Cryptographically random four bytes */
	final byte[] sessionID;
	
	/** 
	 * This is only set when decoding an incoming packet; 
	 * not used (set to -1) when a new header is constructed programmatically.
	 * In the latter case, the body's length will be calculated as needed when
	 * writePacket() is called.
	 */
	final int bodyLength;

	
	@Override public String toString()	
	{
		return "[session:"+Packet.toHex(sessionID)+", seqNum:"+seqNum+", type:"+type+", flags:0x"+Integer.toHexString(flags&FF)+"]";
	}
	
	
	private Header(byte seqNum, byte flags, TAC_PLUS.PACKET.VERSION version, TAC_PLUS.PACKET.TYPE type, byte[] sessionID) {
		this.seqNum = seqNum;
		this.flags = flags;
		this.version = version;
		this.type = type;
		this.sessionID = sessionID;
		this.bodyLength = -1;
	}

	Header(byte flags, TAC_PLUS.PACKET.VERSION version, TAC_PLUS.PACKET.TYPE type, byte[] sessionID) {
		this(
			(byte)1,
			flags,
			version,
			type,
			sessionID
		);
	}

	
	/** Used internally when receiving packets. */
	Header(byte[] bytes)
	{
		version = TAC_PLUS.PACKET.VERSION.forCode(bytes[0]);
		type = TAC_PLUS.PACKET.TYPE.forCode(bytes[1]);
		seqNum = bytes[2];
		flags = bytes[3];
		sessionID = Arrays.copyOfRange(bytes, 4, 8);
		bodyLength = toInt(bytes[8],bytes[9],bytes[10],bytes[11]); 
	}

	/**
	 * Used by both SessionClient and SessionServer to create response packets.
	 * Implicitly allows SINGLE_CONNECT mode, since it returns the same header flags received last
	 * (i.e. encrypted and/or SINGLE_CONNECT).
	 * So if client supports SINGLE_CONNECT (via initial request packet) then the server allows it.
	 * 
	 * @param version
	 * @return
	 * @throws IOException 
	 */
	Header next(TAC_PLUS.PACKET.VERSION version) throws IOException
	{
		if ((FF&seqNum)>=FF) { throw new IOException("Session's sequence numbers exhausted; try new session."); }
		return new Header((byte)((Packet.FF&seqNum)+1), flags, version, type, sessionID);
	}
	
	boolean hasFlag(TAC_PLUS.PACKET.FLAG flag)
	{
		return (flags & flag.code()) != 0;
	}

	/**
	 * Toggles the encryption of the given packet body byte[] returning the result.  
	 * The calculation depends on the given key, and these header fields:
	 * sessionID, version, and seqNum.
	 * @param body
	 * @param key
	 * @param md 
	 * @throws NoSuchAlgorithmException if the MD5 message digest can't be found; shouldn't happen.
	 * @return A new byte[] containing the ciphered/deciphered body; or just 
	 * the unchanged body itself if TAC_PLUS.PACKET.FLAG.UNENCRYPTED is set.
	 */
	byte[] toggleCipher(byte[] body, byte[] key) throws NoSuchAlgorithmException
	{
		if (hasFlag(TAC_PLUS.PACKET.FLAG.UNENCRYPTED)) { return body; }
		MessageDigest md = MessageDigest.getInstance("MD5");
		int length = body.length;
		byte[] pad = new byte[length];
		md.update(sessionID); // reset() not necessary since each digest() resets
		md.update(key);
		md.update(version.code());
		md.update(seqNum);
		byte[] digest=md.digest(); // first digest applies only header info
		System.arraycopy(digest, 0, pad, 0, Math.min(digest.length,length));			
		length -= digest.length;
		int pos = digest.length;
		while (length>0)
		{
			md.update(sessionID);
			md.update(key);
			md.update(version.code());
			md.update(seqNum);
			md.update(Arrays.copyOfRange(pad, pos-digest.length, pos)); // apply previous digest too
			digest=md.digest();
			System.arraycopy(digest, 0, pad, pos, Math.min(digest.length,length));	
			pos += digest.length;
			length -= digest.length;
		}
		byte[] toggled = new byte[body.length];
		for (int i=body.length-1; i>=0; i--)
		{
			toggled[i] = (byte)((body[i] & 0xff) ^ (pad[i] & 0xff));
		}
		return toggled;
	}

	void writePacket(OutputStream out, byte[] body, byte[] key) throws IOException
	{
		int len = body.length;
		ByteArrayOutputStream bout = new ByteArrayOutputStream(12+len);
		bout.write(version.code());
		bout.write(type.code());
		bout.write(seqNum);
		bout.write(flags);
		bout.write(sessionID);
		bout.write(Packet.toBytes4(len));
		try { bout.write(toggleCipher(body, key)); } catch (NoSuchAlgorithmException e) { throw new IOException(e.getMessage()); }
		out.write(bout.toByteArray());
		out.flush();
	}


	
}
