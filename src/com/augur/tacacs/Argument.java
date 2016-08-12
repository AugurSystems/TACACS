package com.augur.tacacs;

/**
 * Used in authorization REQUEST and RESPONSE packets.
 * 
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class Argument
{

	final String attribute;
	final String value;
	final boolean isOptional;
	
	/**
	 * Create an attribute-value pair, also called a argument.
	 * 
	 * @param attribute The non-null String attribute name
	 * @param value The possibly null String value
	 * @param isOptional A boolean flag indicating the value is optional
	 */
	public Argument(String attribute, String value, boolean isOptional)
	{
		this.attribute = attribute;
		this.value = value;
		this.isOptional = isOptional;
	}
	
	/** 
	 * Parses an argument read from a packet.
	 * @param arg The non-null, non-empty String representation of an attribute-value pair.
	 */
	public Argument(String arg)
	{
		String[] args = arg.split("[=*]", 2);
		this.attribute=args[0];
		if (args.length==2) { this.value=args[1]; } else { this.value = null; }
		isOptional = (arg.length() > attribute.length()) && // there is another character after the attribute name
			(arg.charAt(attribute.length()) == '*');
	}


	/** @return The argument's String attribute name. */
	public String getAttribute()
	{
		return attribute;
	}


	/** @return The argument's String value; possibly null. */
	public String getValue()
	{
		return value;
	}


	public boolean isOptional()
	{
		return isOptional;
	}
	
	@Override	public String toString()
	{
		return attribute+(isOptional?"*":"=")+(value==null?"":value);
	}
	
}
