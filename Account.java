class Account
{
	private static String  __sessionid=null;

	public static boolean register(String username,String password)
	{
		return true;
	}

	public static boolean login(String username, String password)
	{
		Account.sessionStart();
		return true;
	}

	public static boolean logout()
	{
		return true;	

	}

	public static boolean checkSession()
	{

		return true;
	}

	public static boolean sessionStart()
	{
		return true;

	}

	public static boolean  owned(String passwd) throws Exception
	{
		
		return false;
	} 	
}
