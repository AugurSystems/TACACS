package com.augur.tacacs;

/**
 * This class has all the byte codes used in the protocol, accessed as inner 
 * classes and enumerations.  For example: TAC_PLUS.AUTHEN.TYPE.ASCII
 * Each code value (a byte) is accessed via the 
 * enumeration's code() method, for example: TAC_PLUS.AUTHEN.TYPE.ASCII.code() 
 * which returns 1.   This naming format mirrors the underscore-separated values defined in 
 * <a href='https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-01'>The TACACS+ Protocol</a>
 * Internet Draft by IETF.  There are some exceptions... 
 * Naming tiers had to be tweaked (e.g. ACTION was added: TAC_PLUS.AUTHEN.ACTION)
 * since the specification overloads some top levels.
 * <p>
 * The use of enumerations ensures compile-time checks of the correct references 
 * passed as method parameters.  
 * (This file may look like a mess, but a modern Java editor will help you
 * navigate subclasses at you type, so the structure is also self-documenting.)
 * </p>
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
	public final class TAC_PLUS
	{
		private TAC_PLUS() {} // private constructors prevent instances (Unfortunately, Java has no true static classes.)
		
		public static enum PRIV_LVL
		{ 
			MAX(0x0f),ROOT(0x0f),USER(1),MIN(0);
			private final byte code; 
			private PRIV_LVL(int code) { this.code=(byte)code; }
			public byte code() { return code; }
		}

		public static final class PACKET
		{
			private PACKET() {}
		
			public static enum VERSION
			{ 
				v13_0(0xc0),v13_1(0xc1);
				private final byte code;
				private VERSION(int code) { this.code=(byte)code; }
				public byte code() { return code; }
				static VERSION forCode(byte b) 
				{
					for (VERSION v : values()) { if (v.code==b) { return v; } }
					return null;
				}
			}
			public static enum TYPE
			{ 
				/** Upgrade connection to TLS.  [New packet type code; appears in "draft-ietf-opsawg-tacacs-04" dated July 8, 2016] */
				START_TLS(0),
				AUTHEN(1),AUTHOR(2),ACCT(3);
				private final byte code;
				private TYPE(int code) { this.code=(byte)code; }
				public byte code() { return code; }
				static TYPE forCode(byte b) 
				{
					for (TYPE t : values()) { if (t.code==b) { return t; } }
					return null;
				}
			}
			public static enum FLAG
			{ 
				UNENCRYPTED(1),SINGLE_CONNECT(4);
				private final byte code;
				private FLAG(int code) { this.code=(byte)code; }
				public byte code() { return code; }
			}
		}
		
		public static final class REPLY
		{
			private REPLY() {}
			public static enum FLAG
			{ 
				NOECHO(1);
				private final byte code;
				private FLAG(int code) { this.code=(byte)code; }
				public byte code() { return code; }
			}
		}
		
		public static final class CONTINUE
		{
			private CONTINUE() {}
			public static enum FLAG
			{ 
				ABORT(1);
				private final byte code;
				private FLAG(int code) { this.code=(byte)code; }
				public byte code() { return code; }
			}
		}
		
		public static final class AUTHEN
		{
			private AUTHEN() {}
			public static enum ACTION
			{ 
				LOGIN(1),CHPASS(2),SENDAUTH(3);
				private final byte code;
				private ACTION(int code) { this.code=(byte)code; }
				public byte code() { return code; }
				public static ACTION forCode(byte b) { for (ACTION e : values()) { if (e.code==b) { return e; } } return null; }
			}
			public static enum TYPE
			{ 
				/** First appeared in "draft-ietf-opsawg-tacacs-02.txt" dated 2016-04-12 */
				NOT_SET(0),
				ASCII(1),PAP(2),CHAP(3),/**@deprecated*/ARAP(4),MSCHAP(5),MSCHAPV2(6);
				private final byte code;
				private TYPE(int code) { this.code=(byte)code; }
				public byte code() { return code; }
				public static TYPE forCode(byte b) { for (TYPE e : values()) { if (e.code==b) { return e; } } return null; }
			}
			public static enum SVC
			{
				/**Appropriate for software apps?*/
				NONE(0),
				/** Usually a shell login? */
				LOGIN(1),
				/**To escalate privileges, e.g. Unix 'su' command*/
				ENABLE(2),
				PPP(3),ARAP(4),PT(5),RCMD(6),X25(7),NASI(8),FWPROXY(9);
				private SVC(int code) { this.code=(byte)code; }
				private final byte code;
				public byte code() { return code; }
				public static SVC forCode(byte b) { for (SVC e : values()) { if (e.code==b) { return e; } } return null; }
			}
			public static enum METH
			{
				NOT_SET(0),NONE(1),KRB5(2),LINE(3),ENABLE(4),LOCAL(5),TACACSPLUS(6),GUEST(8),RADIUS(0x10),KRB4(0x11),RCMD(0x20);
				private METH(int code) { this.code=(byte)code; }
				private final byte code;
				public byte code() { return code; }
				public static METH forCode(byte b) { for (METH e : values()) { if (e.code==b) { return e; } } return null; }
			}
			public static enum STATUS
			{
				PASS(1),FAIL(2),GETDATA(3),GETUSER(4),GETPASS(5),RESTART(6),ERROR(7),FOLLOW(0x21);
				private STATUS(int code) { this.code=(byte)code; }
				private final byte code;
				public byte code() { return code; }
				public static STATUS forCode(byte b) { for (STATUS e : values()) { if (e.code==b) { return e; } } return null; }
			}
		}
		
		public static final class AUTHOR
		{
			private AUTHOR() {}
			public static enum STATUS
			{
				PASS_ADD(1),PASS_REPL(2),FAIL(0x10),ERROR(0x11),FOLLOW(0x21); 
				private STATUS(int code) { this.code=(byte)code; }
				private final byte code;
				public byte code() { return code; }
				public static STATUS forCode(byte b) { for (STATUS e : values()) { if (e.code==b) { return e; } } return null; }
			}
		}
		
		public static final class ACCT
		{
			private ACCT() {}
			public static enum FLAG
			{ 
				START(2),STOP(4),WATCHDOG(8);
				private final byte code;
				private FLAG(int code) { this.code=(byte)code; }
				public byte code() { return code; }
			}
			public static enum STATUS
			{
				SUCCESS(1),ERROR(2),FOLLOW(0x21); 
				private STATUS(int code) { this.code=(byte)code; }
				private final byte code;
				public byte code() { return code; }
				public static STATUS forCode(byte b) { for (STATUS e : values()) { if (e.code==b) { return e; } } return null; }
			}
		}

	}