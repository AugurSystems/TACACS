package com.augur.tacacs;

import java.net.Socket;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.TimeoutException;

/**
 * This is a placeholder for a TACACS+ server implementation;
 * a skeleton implementation is started here, but there is no reference to any
 * AAA configuration, so it can't actually be used to provide 
 * authentication/authorization/accounting services yet.  
 * However, the basic packet handling is provided.
 * <p>
 * The TACACS+ Protocol (version 1.78) is defined at 
 * <a href='https://tools.ietf.org/html/draft-grant-tacacs-02'>IETF.org</a>.
 *
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */

public class TacacsServer extends TacacsReader
{


	private TacacsServer(Socket socket, String key) throws IOException
	{
		super(socket, key);
	}

	
	
	
	public static void main(String[] args) throws IOException, TimeoutException
	{
		String key = args[0];
		ServerSocket ss = new ServerSocket(PORT_TACACS);
		while (true)
		{
			Socket s = ss.accept();
			TacacsServer ts = new TacacsServer(s, key);
			ts.start();
		}
	}
	
	
}
