package com.augur.tacacs;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class SessionClient extends Session
{
	private static final int TIMEOUT_MILLIS = 5000; // TODO: don't hard-code
	private static final boolean DEBUG = false;
	private final UserInterface ui;
	
	/** Client-side constructor; end-user should use newSession() in Tacacs. */
	SessionClient(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, Tacacs tacacs)
	{
		this(svc, port, rem_addr, priv_lvl, tacacs, null);
	}
	
	/** 
	 * Client-side constructor, only needed for interactive (ASCII) login, 
	 * which needs to prompt user for info via a UserInterface. 
	 */
	SessionClient(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, Tacacs tacacs, UserInterface ui)
	{
		super(svc, port, rem_addr, priv_lvl, tacacs, null);
		this.ui = ui;
	}
	
	/**
	 * Calls notify() to inform public methods when the final reply packet has been received.
	 * @param p
	 * @throws IOException 
	 */
	@Override synchronized void handlePacket(Packet p) throws IOException
	{
		super.handlePacket(p); // stores firstPacket, for isSingleConnectMode()
		if (DEBUG) { System.out.println("Received <-- "+p); }
		switch(p.header.type)
		{
			case AUTHEN: // must be a Reply from the server
				AuthenReply authenReply = (AuthenReply)p;
				switch(authenReply.status)
				{
					case PASS:
						end(p);
						break;
					case GETDATA: // generic authen questions, e.g. favorite teacher?  Only used during ASCII (interactive) AUTHEN LOGIN
						if (ui==null) { throw new IOException("No interactive user interface available."); } // shouldn't happen
						String data = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TAC_PLUS.REPLY.FLAG.NOECHO), authenReply.status); // blocks for user input
						tacacs.write(new AuthenContinue
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							data,
							FLAG_ZERO
						));
						break;
					case GETUSER: // only used during ASCII (interactive) AUTHEN LOGIN
						if (ui==null) { throw new IOException("No interactive user interface available."); }
						String username = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TAC_PLUS.REPLY.FLAG.NOECHO), authenReply.status); // blocks for user input
						tacacs.write(new AuthenContinue
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							username,
							FLAG_ZERO
						));
						break;
					case GETPASS:
						if (ui==null) { throw new IOException("No interactive user interface available."); }
						String password = ui.getUserInput(authenReply.server_msg, authenReply.hasFlag(TAC_PLUS.REPLY.FLAG.NOECHO), authenReply.status); // blocks for user input
						tacacs.write(new AuthenContinue
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							password,
							FLAG_ZERO
						));
						break;
					case RESTART: // per spec, server didn't like our authen_type; TODO: try types? 
					case ERROR: // per spec, "...should proceed as if that host could not be contacted..."
					case FAIL:
					case FOLLOW: // not implemented, so spec says must treat as FAIL; TODO implement, and remember the working server
					default:
						end(p);
						break;
				}
				break;
			case AUTHOR:
				end(p);
				break;
			case ACCT:
				end(p);
				break;
		}
	}
	
	
	/**
	 * @return An AuthenReply representing the result of the login attempt
	 * @throws java.util.concurrent.TimeoutException
	 * @throws java.io.IOException
	 */
	public synchronized AuthenReply authenticate_ASCII() throws TimeoutException, IOException
	{
		tacacs.write(new AuthenStart
		(
			new Header(TAC_PLUS.PACKET.VERSION.v13_0, TAC_PLUS.PACKET.TYPE.AUTHEN,id), 
			TAC_PLUS.AUTHEN.ACTION.LOGIN, 
			TAC_PLUS.PRIV_LVL.MIN.code(), 
			TAC_PLUS.AUTHEN.TYPE.ASCII, 
			TAC_PLUS.AUTHEN.SVC.NONE, 
			null, // server will prompts for username
			port, 
			rem_addr, 
			null // server will prompt for password
		)); 
		waitForeverForReply();
		if (!result.getHeader().hasFlag(TAC_PLUS.PACKET.FLAG.SINGLE_CONNECT)) { tacacs.shutdown(); }
		return (AuthenReply)result;
	}

	
	/**
	 * @param username
	 * @param password
	 * @return An AuthenReply representing the result of the login attempt
	 * @throws java.util.concurrent.TimeoutException
	 * @throws java.io.IOException
	 */
	public synchronized AuthenReply authenticate_PAP(String username, String password) throws TimeoutException, IOException 
	{
		tacacs.write(new AuthenStart
		(
			new Header(TAC_PLUS.PACKET.VERSION.v13_1, TAC_PLUS.PACKET.TYPE.AUTHEN,id), 
			TAC_PLUS.AUTHEN.ACTION.LOGIN, 
			TAC_PLUS.PRIV_LVL.MIN.code(), 
			TAC_PLUS.AUTHEN.TYPE.PAP, 
			TAC_PLUS.AUTHEN.SVC.NONE, 
			username, 
			port, 
			rem_addr, 
			password
		)); 
		waitForReply(TIMEOUT_MILLIS);
		if (!result.getHeader().hasFlag(TAC_PLUS.PACKET.FLAG.SINGLE_CONNECT)) { tacacs.shutdown(); }
		return (AuthenReply)result;
	}

	
	/**
	 * @param username
	 * @param authen_meth
	 * @param authen_type
	 * @param authen_svc
	 * @param args
	 * @return An AuthorReply representing the result of the authorization attempt
	 * @throws java.util.concurrent.TimeoutException
	 * @throws java.io.IOException
	 */
	public synchronized AuthorReply authorize(String username, TAC_PLUS.AUTHEN.METH authen_meth, TAC_PLUS.AUTHEN.TYPE authen_type, TAC_PLUS.AUTHEN.SVC authen_svc, Argument[] args) throws TimeoutException, IOException 
	{
		tacacs.write(new AuthorRequest
		(
			new Header(TAC_PLUS.PACKET.VERSION.v13_0, TAC_PLUS.PACKET.TYPE.AUTHOR,id), 
			authen_meth,
			(byte)0,
			authen_type,
			authen_svc,
			username,
			port,
			rem_addr,
			args
		)); 
		waitForReply(TIMEOUT_MILLIS);
		if (!isSingleConnectMode()) { tacacs.shutdown(); }
		return (AuthorReply)result;
	}
	
	/**
	 * @param flags
	 * @param username
	 * @param authen_meth
	 * @param authen_type
	 * @param authen_svc
	 * @param args One of TAC_PLUS.ACCT.FLAG.START, STOP, WATCHDOG, or WATCHDOG+START; if not, an IOException will be thrown before sending to the server.
	 * @return An AcctReply representing the result of the accounting attempt
	 * @throws java.util.concurrent.TimeoutException
	 * @throws java.io.IOException
	 */
	public synchronized AcctReply account(byte flags, String username, TAC_PLUS.AUTHEN.METH authen_meth, TAC_PLUS.AUTHEN.TYPE authen_type, TAC_PLUS.AUTHEN.SVC authen_svc, Argument[] args) throws TimeoutException, IOException 
	{
		if (
			flags!=TAC_PLUS.ACCT.FLAG.START.code() &&
			flags!=TAC_PLUS.ACCT.FLAG.STOP.code() &&
			flags!=TAC_PLUS.ACCT.FLAG.WATCHDOG.code() &&
			flags!=(TAC_PLUS.ACCT.FLAG.WATCHDOG.code()+TAC_PLUS.ACCT.FLAG.START.code())
		) { throw new IOException("Invalid Accounting flags"); }
		tacacs.write(new AcctRequest
		(
			new Header(TAC_PLUS.PACKET.VERSION.v13_0, TAC_PLUS.PACKET.TYPE.AUTHOR,id), 
			flags,
			authen_meth,
			TAC_PLUS.PRIV_LVL.USER.code(),
			authen_type,
			authen_svc,
			username,
			port,
			rem_addr,
			args
		)); 
		waitForReply(TIMEOUT_MILLIS);
		if (!isSingleConnectMode()) { tacacs.shutdown(); }
		return (AcctReply)result;
	}

	/**
	 * Authorizes, assuming authen_meth=TACACS+, authen_type=PAP, and authen_svc=LOGIN. 
	 * @param username
	 * @param args
	 * @return An AuthorReply representing the result of the authorization attempt
	 * @throws java.util.concurrent.TimeoutException
	 * @throws java.io.IOException
	 */
	public synchronized AuthorReply authorize(String username, Argument[] args) throws TimeoutException, IOException 
	{
		return authorize(username, TAC_PLUS.AUTHEN.METH.TACACSPLUS, TAC_PLUS.AUTHEN.TYPE.PAP, TAC_PLUS.AUTHEN.SVC.LOGIN, args);
	}


	
}
