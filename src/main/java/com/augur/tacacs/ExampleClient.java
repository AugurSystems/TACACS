package com.augur.tacacs; // You would be coding in a different package
import com.augur.tacacs.*;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.security.AccessControlException;
import java.util.concurrent.TimeoutException;

/**
 * This is an example TACACS+ authentication, followed by authorization.
 * For this example, it is assumed that the TACACS+ server has an attribute
 * named "role" associated with users' permissions in your application.
 * <p>
 * There are a lot of exceptions thrown in the login() example for completeness,
 * but you might instead write to a log.  So pay closer attention to 
 * the calls on TacacsClient and their reply packets. 
 * </p>
 * @author Chris.Janicki@augur.com
 * Copyright Apr 25, 2016 Augur Systems, Inc.  All rights reserved.
 */
public class ExampleClient
{

	/**
	 * Authenticate via PAP, then authorize.
	 * 
	 * @param tacacsHost The String host name or address of the TACACS+ server; 
	 *   May be a comma and/or space-separated list.  If a non-standard (49) port
	 *   is required, it should be appended to the host, after a colon (':').
	 * @param tacacsKey The String secret key shared with the TACACS+ server.
	 *   May be a comma and/or space-separated list, corresponding to multiple
	 *   hosts.
	 * @param username  The String subject identifier.
	 * @param password  The String password.
	 * @return  The String value of the "role" attribute returned from 
	 *   the TACACS+ server for the authorized subject; possibly null.
	 * @throws AccessControlException if the subject (user) is authenticated, 
	 * @throws InvalidObjectException if the subject (user) did not authenticate 
	 *   but authorization fails
	 * @throws TimeoutException if contacting the TACACS+ server takes too long
	 * @throws IOException if there is any underlying problem contacting the 
	 *   TACACS+ server
	 */
	public String login(String tacacsHost, String tacacsKey, String username, String password) throws IOException, TimeoutException, AccessControlException, InvalidObjectException
	{
		TacacsClient tc = new TacacsClient(tacacsHost, tacacsKey, 10000, false); // 10 second time-out for contacting TACACS+, and don't attempt single-connect for test simplicity
		SessionClient authenSession = tc.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code()); // IO or Timeout exceptions if can't contact TACACS+
		AuthenReply authentication = authenSession.authenticate_PAP(username, password);
		if (authentication.isOK()) 
		{
			// Need fresh session for authorization...
			SessionClient authorSession = tc.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, "console", "localhost", TAC_PLUS.PRIV_LVL.USER.code()); // IO or Timeout exceptions if can't contact TACACS+
			AuthorReply authorization = authorSession.authorize(
				username, 
				TAC_PLUS.AUTHEN.METH.TACACSPLUS, // informational only: where we authenticated (it was via TACACS+, just above, but could have been some external system) 
				TAC_PLUS.AUTHEN.TYPE.PAP, // informational only: how we authenticated (we used id/pw)
				TAC_PLUS.AUTHEN.SVC.LOGIN, // informational only: the service that authenticated (we were logging into a box?)
				new Argument[] { new Argument("service=MyApplication") } // "service" is required! (directs TACACS+ to a subset of configuration)
			); 
			tc.shutdown(); // close any persistent connection (if server supported SINGLE_CONNECT mode; otherwise ignored)
			if (authorization.isOK()) 
			{
				return authorization.getValue("role"); // TACACS+ returned all attributes for given user+service; we want "role" for this example
			}
			else // something went wrong with authorization
			{ 
				// The server may have explained in either 'data' or 'serverMsg' fields...
				// Note that 'serverMsg' is usually intended for presentation to the user.
				if (authorization.getData()!=null) { throw new AccessControlException("Problem authorizing '"+username+"': \""+authorization.getData()+"\""); }
				if (authorization.getServerMsg()!=null) { throw new AccessControlException("Problem authorizing '"+username+"': \""+authorization.getServerMsg()+"\""); }
				else { throw new AccessControlException("User '"+username+"' is authenticated but not authorized."); }
			}
		}
		else // did not authenticate
		{
			// The server may have explained in either 'data' or 'serverMsg' fields...
			// Note that 'serverMsg' is usually intended for presentation to the user.
			if (authentication.getData()!=null) { throw new InvalidObjectException("User ("+username+") not authenticated: "+authentication.getData()); }
			else if (authentication.getServerMsg()!=null) { throw new InvalidObjectException("User ("+username+") not authenticated: "+authentication.getServerMsg()); }
			else { throw new InvalidObjectException("User ("+username+") not authenticated."); }
		}
		
	}



}
