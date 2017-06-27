package com.augur.tacacs;
import java.io.Console;

/**
 * This class handles interactive authentication requests; 
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public abstract class UserInterface
{
	protected String username=null;
	
	/**
	 * 
	 * @param prompt The prompt to be shown to the user, e.g. "Password:"
	 * @param noEcho A boolean indicating if the human user's input should not be echoed to the screen, to protect secret info like passwords.
	 * @param getWhat The TAC_PLUS.AUTHEN.STATUS, used to determine what type of information is requested, e.g. username, password, etc.
	 * @return 
	 */
	public abstract String getUserInput(String prompt, boolean noEcho, TAC_PLUS.AUTHEN.STATUS getWhat);
	
	
	/**
	 * @return The username given to this UserInterface; possibly null if not yet collected.
	 */
	public final String getUsername() { return username; }
	
	
	/**
	 * Creates an instance that that will return the given username and password 
	 * when prompted; useful for simulating a PAP-like response to an interactive (ASCII) interface.
	 */
	public static final UserInterface getPAPInstance(final String usernameLocal, final String password)
	{
		return new UserInterface()
		{
			{
				this.username = usernameLocal;
			}
			@Override public String getUserInput(String prompt, boolean noEcho, TAC_PLUS.AUTHEN.STATUS getWhat)
			{
				switch(getWhat)
				{
					case GETUSER: 
						return username;
					case GETPASS: 
						return password;
					case GETDATA: 
					default:
						// don't have any info for GETDATA requests in this simple PAP implementation
						return null;
				}
			}
		};
	}
	
	
	/**
	 * Creates an instance that prompts the console user to enter data after prompts.
	 * @prompt A String prompt to be displayed for the user on the console.
	 * @noEcho A boolean indicating if the user-entered text should be hidden from the console; usually for passwords.
	 */
	public static final UserInterface getConsoleInstance()
	{
		return new UserInterface()
		{
			@Override public String getUserInput(String prompt, boolean noEcho, TAC_PLUS.AUTHEN.STATUS getWhat)
			{
				Console console = System.console();
				if (console == null) { System.out.println("No console available!"); return null; }
				System.out.println();
				System.out.print(prompt);
				String input = noEcho? new String(console.readPassword()) : console.readLine();
				if (getWhat == TAC_PLUS.AUTHEN.STATUS.GETUSER) { this.username = input; }
				return input;
			}
		};
	}

	
	
}
