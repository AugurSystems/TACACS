package com.augur.tacacs;

/**
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public interface AuthenListener
{
	public String getData(String prompt, boolean noEcho);
	public String getPass(String prompt, boolean noEcho);
	public String getUser(String prompt, boolean noEcho);
}
