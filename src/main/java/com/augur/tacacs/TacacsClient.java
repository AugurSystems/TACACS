package com.augur.tacacs;



import java.net.Socket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeoutException;

/**
 * This is a TACACS+ client, implementing methods for authentication, 
 * authorization, and accounting.  For usage in your app, see the static 
 * example methods at the end of the source code.
 * <p>
 * The TACACS+ Protocol (version 1.78) is defined at 
 * <a href='https://tools.ietf.org/html/draft-grant-tacacs-02'>IETF.org</a>.
 * You really need to read this to do anything beyond the simple login/authorization
 * examples here.  It's a very flexible protocol, but confusing outside of its 
 * historical usage... Many fields are required that
 * don't exactly correspond to an application's scope, so their definitions require 
 * some interpretation.  For example, a "port" field historically refers to 
 * a physical port within some hardware, e.g. a telephone modem line's connector
 * on terminal server hardware.  And "rem_addr" would traditionally contain the 
 * caller's telephone number.  Translating these for usage with a software 
 * application's login screen is weird.   
 * </p>
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */

public class TacacsClient extends Object
{
	private String[] hosts, keys;
	private int[] ports;
	private final int timeoutMillis;
	final boolean singleConnect;
	final boolean unencrypted;
	/** Note: instance methods are synchronized to protect access to tacacs. */
	private TacacsReader tacacs;

	/**
	 * Constructs a new TacacsClient that may be used for multiple calls to newSession().
	 *
	 * @param host The comma and/or space-separated list of hostnames or
	 *   IP addresses of TACACS+ servers; optionally with colon-separated port.
	 * @param key The comma and/or space-separated list of secret keys shared with each TACACS+ server.
	 * @param timeoutMillis  The socket connection time-out.  Note this should be
	 *   less than one minute (or whatever AJAX call time-out is used in browsers) to
	 *   avoid confusing error messaging from browsers when AJAX calls time-out on
	 *   the browser before the socket elegantly times-out in TrapStation code.
	 * @param singleConnect A boolean indicating if a single socket connection
	 *   can be reused for multiple sessions, if the server also agrees;
	 *   it seems this must be set 'false' for Cisco ACS which closes socket
	 *   despite offering to accept SINGLE_CONNECT mode.
	 * @param unencrypted A boolean indicating if the payload should remain unencrypted
	 *   during transmission.
	 */
	public TacacsClient(String host, String key, int timeoutMillis, boolean singleConnect, boolean unencrypted)
	{
		this.timeoutMillis = timeoutMillis;
		this.keys = key.split("[,\\s]+");
		this.hosts = host.split("[,\\s]+");
		this.ports = new int[hosts.length];
		this.singleConnect = singleConnect;
		this.unencrypted = unencrypted;
		for (int i=hosts.length-1; i>=0; i--)
		{
			try 
			{
				// Use Java URI class to parse hostname and port; for both IPv4 and IPv6.
				URI uri = new URI("http://" + hosts[i]); 
				hosts[i] = uri.getHost();
				ports[i] = uri.getPort();
				if(ports[i] == -1) 
				{
					Logging.logger().fine("TACACS+: No port assigned for host, \""+hosts[i]+"\".  " +
						"Using default port "+TacacsReader.PORT_TACACS+" instead.");
					ports[i] = TacacsReader.PORT_TACACS;
				}
			} 
			catch (URISyntaxException e) 
			{
				Logging.logger().fine("TACACS+: Bad port assigned for host, \""+hosts[i]+"\".  " +
					"Using default port "+TacacsReader.PORT_TACACS+" instead.");
				ports[i] = TacacsReader.PORT_TACACS;
			}
		}

	}
	/**
	 * Constructs a new TacacsClient that may be used for multiple calls to newSession().
	 *
	 * @param host The comma and/or space-separated list of hostnames or
	 *   IP addresses of TACACS+ servers; optionally with colon-separated port.
	 * @param key The comma and/or space-separated list of secret keys shared with each TACACS+ server.
	 * @param timeoutMillis  The socket connection time-out.  Note this should be
	 *   less than one minute (or whatever AJAX call time-out is used in browsers) to
	 *   avoid confusing error messaging from browsers when AJAX calls time-out on
	 *   the browser before the socket elegantly times-out in TrapStation code.
	 * @param singleConnect A boolean indicating if a single socket connection
	 *   can be reused for multiple sessions, if the server also agrees;
	 *   it seems this must be set 'false' for Cisco ACS which closes socket
	 *   despite offering to accept SINGLE_CONNECT mode.
	 */
	public TacacsClient(String host, String key, int timeoutMillis, boolean singleConnect)
	{
		this(host, key, timeoutMillis, singleConnect, false);
	}

	/**
	 * Constructs a new TacacsClient, using the default connection time-out (5 seconds).
	 * @param host The comma and/or space-separated list of hostnames or IP addresses of TACACS+ servers; optionally with colon-separated port.
	 * @param key The comma and/or space-separated list of secret keys shared with each TACACS+ server.
	 */
	public TacacsClient(String host, String key)
	{
		this(host, key, 5000, false);
	}
	

	
	/**
	 * Creates a new session and registers it with communications thread, to process
	 * the server's reply.  Note that a session may only be used once, per protocol specs!  
 So if you need to authenticate a user, then ask for authorizations, that requires two
 sessions.  (However, those sessions will reuse the underlying socket 
 connection to the remote TACACS+ server, so it's not too inefficient.)  
 Synchronized to protect creation/shutdown of TacacsReader.
	 * 
	 * @param svc  The TAC_PLUS.AUTHEN.SVC requesting the action
	 * @param port The String port identifier where the user is attached; 
	 *   e.g. a physical port number on a terminal server, or maybe just "console" for an app.
	 * @param rem_addr  The String description of the user's location; 
	 *   e.g. a network address, or a geographic equipment location.
	 * @param priv_lvl  The byte privilege level of the requesting user;  range is 0-15; 
	 *   e.g. TAC_PLUS.PRIV_LVL.USER.code()  (a pre-defined value=1)
	 * @return a SessionClient that can be used for one authentication, 
	 *   authorization, or accounting request.
	 * @throws SocketTimeoutException (a subclass of IOException!) if the connection isn't made before the timeout.
	 * @throws java.io.IOException if there is any problem, other than SocketTimeoutException.
	 */
	public synchronized SessionClient newSession(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl) {
		TacacsReader t = getTacacs(); // throws IOException and SocketTimeoutException (a subclass of IOException!)
		SessionClient s = new SessionClient(svc, port, rem_addr, priv_lvl, t, singleConnect, unencrypted);
		t.addSession(s);
		return s;
	}
	
	/**
	 * This is the same as the other newSessionInteractive(), except it includes a
	 * UserInterface parameter.  This is only needed for interactive authentications,
	 * i.e. authentication type = TAC_PLUS.AUTHEN.TYPE.ASCII.  
	 * Synchronized to protect creation/shutdown of TacacsReader.
	 */
	public synchronized SessionClient newSessionInteractive(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, UserInterface ui) {
		TacacsReader t = getTacacs(); // throws IOException and SocketTimeoutException (a subclass of IOException!)
		SessionClient s = new SessionClient(svc, port, rem_addr, priv_lvl, t, ui, singleConnect, unencrypted);
		t.addSession(s);
		return s;
	}
	
	/**
	 * Synchronized to protect creation/shutdown of TacacsReader.
	 */
	public synchronized void shutdown()
	{
		if (tacacs!=null && !tacacs.isShutdown()) 
		{
			tacacs.shutdown(); 
			tacacs=null; 
		}
	}
	
		
	/**
	 * Synchronized to protect creation/shutdown of TacacsReader.
	 */
	private synchronized TacacsReader getTacacs() throws TacacsException {
		if (tacacs==null || tacacs.isShutdown())
		{
			tacacs = null;
			Socket sock=null;
			for (int i=0; i<hosts.length; i++)
			{
				try 
				{ 
					//System.out.println("TACACS+: Trying server at "+hosts[i]+":"+ports[i]);
					sock = new Socket();
					sock.connect(new InetSocketAddress(hosts[i],ports[i]), timeoutMillis); // throws IOException
					String key = (i<keys.length) ? keys[i] : keys[keys.length-1]; // reuse last only if not enough
					tacacs = new TacacsReader(sock, key);
					tacacs.start();
					Logging.logger().fine("TACACS+: Connected to server at "+hosts[i]+":"+ports[i]);
					return tacacs;
				}
				catch(IOException ioe) 
				{ 
					if (sock!=null) { try { sock.close(); } catch (IOException ioe2) { } }
					tacacs = null;
					Logging.logger().severe("TACACS+: Unable to contact TACACS+ server @ "+hosts[i]+" ("+ioe+")");
				}
			}
			if (tacacs == null) { throw new TacacsException("Unable to contact any TACACS+ server(s)."); }
		}
		return tacacs;
	}
	

//	/**
//	 * This is a convenience method that creates a new session using some default 
//	 * default parameters, then attempts to authenticate.  For full control, 
//	 * instantiate your own SessionClient with your own parameters, then call its 
//	 * authenticate_PAP() method.
//	 * 
//	 * @param username The String id for authentication
//	 * @param password The String password for authentication
//	 * @return AuthenReply
//	 * @throws IOException if there is a problem communicating with the TACACS+ server.
//	 * @throws TimeoutException if there is a time-out waiting for the TACACS+
//	 *   server to respond to the successfully transmitted authentication request.
//	 */
//	public AuthenReply authenticate_PAP(String username, String password) throws IOException, TimeoutException
//	{
//		SessionClient session = newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code()); // throws exceptions if can't contact TACACS+
//		return session.authenticate_PAP(username, password);
//	}
	

	// =========================== EXAMPLES ======================================
	
	/**
	 * Example test ground.
	 */
	public static void main(String[] args) throws IOException, TimeoutException
	{
		if (args.length==0) { System.out.println("java -jar tacacs.jar <host> <key>"); }
		else
		{
			String host = args.length>0 ? args[0] : null;
			String key = args.length>1 ? args[1] : "augur.com";
			TacacsClient tc = new TacacsClient(host, key);

			// substitute another example here for testing
			exampleAuthenInteractive(args, tc); 
			// If you run another command, first check tc.isStillConnected().
			tc.shutdown();
		}
	}
	
	
	/**
	 * Authenticate by prompting for requested data at console; 
	 * usually the TACACS+ server asks for a username, then a password.
	 * If successful authentication, then get authorizations too.
	 * 
	 * @param args  The command line String[] arguments; 
	 * the TACACS+ server's host name or address must be the first argument.
	 */
	private static void exampleAuthenInteractive(String[] args, TacacsClient tc) throws IOException, TimeoutException
	{
		UserInterface ui = UserInterface.getConsoleInstance(); // The UI will store the entered username... We'll need it for authorization.		
		SessionClient s = tc.newSessionInteractive(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code(), ui);
		AuthenReply authen = s.authenticate_ASCII();
		if (authen.server_msg!=null) System.out.println("> \""+authen.server_msg+"\"");
		System.out.println("TACACS+: Login success? " + authen.isOK());
		System.out.println();
		if (authen.isOK()) { exampleAuthorize(ui.getUsername(), tc); }
	}
	
	/**
	 * Authenticate via PAP.
	 * Usage: java -cp . TacacsClient [serverHost] [username] [password]
	 * 
	 * @param args  The command line String[] arguments; 
	 * the TACACS+ server's host name or address must be the first argument;
	 * the username is second, and the password is the third argument.
	 */
	private static void exampleAuthenPAP(String[] args, TacacsClient tc) throws IOException, TimeoutException
	{
		SessionClient s = tc.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code());
		AuthenReply authen = s.authenticate_PAP(args[1], args[2]);
		if (authen.server_msg!=null) System.out.println("> \""+authen.server_msg+"\"");
		System.out.println("TACACS+: Login success? " + authen.isOK());
		System.out.println();
		if (authen.isOK()) { exampleAuthorize(args[1], tc); }
	}
	
	/**
	 * Get "trapstation" service authorizations for the given user.
	 * Usually this is called after the user has been authenticated in a previous
	 * session.
	 * <p>
	 * Dev note: AuthorReply.getArguments() would return an Argument[] containing
	 * all the authorization strings (key=value) returned by the server for the 
	 * requested 'username' and 'service'.  Your app can use those strings to limit 
	 * privileged features.  The TACACS+ server admin would first have to edit the 
	 * server's configuration to add the "service" for your app, then associate
	 * permission keys/values with users (or groups) in the server's configuration.
	 * Those key/values are returned to you based on the authenticated username.  
	 * The fact that a username has been authenticated is trusted.  The server will
	 * tell you the key/values for any username + service combination, but it's up
	 * to your app to first authenticate the user, usually with a previous TACACS+
	 * authentication session, although technically that could be done elsewhere
	 * (and the TAC_PLUS.AUTHEN.METH argument provides a way for you to say that).
	 * </p>
	 */
	private static void exampleAuthorize(String username, TacacsClient tc) throws IOException, TimeoutException
	{
		SessionClient s = tc.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code());
		AuthorReply author = s.authorize(
			username, 
			TAC_PLUS.AUTHEN.METH.TACACSPLUS, 
			TAC_PLUS.AUTHEN.TYPE.ASCII, 
			TAC_PLUS.AUTHEN.SVC.LOGIN, 
			new Argument[] { new Argument("service=trapstation") }); // The "service" attribute is required!!!  "trapstation" is an example app for which I want to know the user's permitted role
		if (author.server_msg!=null) System.out.println("> \""+author.server_msg+"\"");
		System.out.println("TACACS+: Authorization success? "+ author.isOK());
		System.out.println();
	}
	
	/**
	 * Start an accounting record.
	 * Usually this is called after the username has been authenticated in a previous
	 * session.  And a later session should stop the record.  
	 * 
	 * Disclaimer: I don't really understand the accounting aspect of TACACS.  
	 * Consider this example a rough skeleton.  It was created just to test the 
	 * basic I/O.
	 */
	private static void exampleAccount(String username, TacacsClient tc) throws IOException, TimeoutException
	{
		SessionClient s = tc.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code());
		AcctReply acct = s.account
		(
			TAC_PLUS.ACCT.FLAG.START.code(), // starting a record
			username, // who does this record apply to
			TAC_PLUS.AUTHEN.METH.TACACSPLUS, // What system did we use to previously authenticate this user...
			TAC_PLUS.AUTHEN.TYPE.ASCII, // and what login protocol was used...
			TAC_PLUS.AUTHEN.SVC.LOGIN, // and what service was requesting the authentication.
			new Argument[] { new Argument("cmd=ssh -l root payrollServer") } // Record stuff, e.g. which command was executed.
		);
		if (acct.server_msg!=null) System.out.println("> \""+acct.server_msg+"\"");
		System.out.println("TACACS+: Accounting success? "+ acct.isOK());
		System.out.println("");
	}
	
	
	
}
