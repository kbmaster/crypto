import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

class Account
{	
	private static String __uid="";
	
	public static boolean register(String username,String password)
	{
		/*String hashPass=Account.hashPass(password);
		String sqlInsertUser = "INSERT INTO Users (UserID,UserName, Password) values (NULL,'"+ username+ "','"+ hasPass+"');";
            	Connection con = Account.getConnection();
            	Statement st = con.createStatement();
            	st.execute(sqlInsertUser);
		con.close();
		*/
		
		Account.__uid="1";
		return true;
	}

	public static boolean login(String username, String password)
	{
		/*String hashPass=Account.hashPass(password);
		String sqlUser = "SELECT UserID from Users where users_name = '" + user + "' and password = '"+ hashPass+"';";
        	Connection con = DataBaseController.conectarBD();
        	Statement st = con.createStatement();
        	ResultSet rs = st.executeQuery(sqlUser);

        	if(rs.next())
		{
           		 con.close();
			 if(!Account.SessionStart(rs.getObject("UserID"))) throw new Exception("Error aliniciar sesion");
			 return true;
        	}
        	else
		{ 
            		con.close();
			return false;
		}*/

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

	
	public  static String getID()
	{
		return Account.__uid;
	}


	public static boolean sessionStart()
	{
	        /*MessageDigest md = MessageDigest.getInstance("SHA-1");
            	String sssionID  = new String(md.digest());
		
		

		String sqlInsertUser = "INSERT INTO Sessions (UserID, SessionID) values ("+userID+",'"+sessionID+"')";
                Connection con = Account.getConnection();
                Statement st = con.createStatement();
                st.execute(sqlInsertUser);*/
		return true;
	}

	public static boolean  owned(String passwd) throws Exception
	{
		/*String phash = Account.hashPass(passwd);
		String hash= phash.substring(0,5);
		String suffixHash = phash.substring(5).toUpperCase();		

		
		// Se abre la conexion
		URL url = new URL("https://api.pwnedpasswords.com/range/"+hash);
        	URLConnection conexion = url.openConnection();
	        conexion.setRequestProperty("User-Agent", "App de Prueba");
		conexion.connect();
		
		// Lectura
	        InputStream is = conexion.getInputStream();
         	BufferedReader br = new BufferedReader(new InputStreamReader(is));
         	char[] buffer = new char[1000];
         	int leido;
         	while ((leido = br.read(buffer)) > 0)
		{ 
			String [] response = new String(buffer, 0, leido).split("\\r?\\n");
		

		for (String line : response) 
			if (line.startsWith(suffixHash)) return true;

		}*/

		return false;
	} 

	private static String hashPass( String pass) throws Exception
	{
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] array = md.digest(pass.getBytes());
            StringBuffer sb = new StringBuffer();

            	for (int i = 0; i < array.length; ++i) 
		   sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
            
            return sb.toString();
    
	}

	/*private static Connection getConnection() throws Exception
	{
		connection = DriverManager.getConnection("jdbc:sqlite:./data/Usuarios.db");
		if(connection==null)throw new Exception("Error de  conexion");
		return connection;
	}*/

		
}
