import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;

class Account
{	
	private static String __uid="";
	private static String __dbhost;	
	private static String __dbname;
	private static String __dbuser;
	private static String __dbpasswd;
	private static String __sessiondir="./";
	
	public static boolean register(String username,String password) throws Exception
	{
		String hashPass=Account.hashPass(password);
		String sqlInsertUser = "INSERT INTO Users (Username, Password) values (?,?);";
            	Connection con = Account.getConnection();

            	PreparedStatement ps = con.prepareStatement(sqlInsertUser,Statement.RETURN_GENERATED_KEYS);
		
		ps.setString(1,username);
		ps.setString(2,hashPass);
		
            	ps.executeUpdate();

		//Retornar el userid generado
		ResultSet rs = ps.getGeneratedKeys();
		rs.next();
		Account.__uid=rs.getString(1);		

		con.close();
		
		return true;
	}

	public static boolean login(String username, String password) throws Exception
	{	

		String hashPass=Account.hashPass(password);
                String sqlLogin = "SELECT UserID from Users where Username=? AND Password=?";
                Connection con = Account.getConnection();
		
		PreparedStatement ps = con.prepareStatement(sqlLogin);
		ps.setString(1,username);
                ps.setString(2,hashPass);

		ResultSet rs = ps.executeQuery();
		
        	if(rs.next())
		{
			 Account.__uid=rs.getString("UserID");
			 con.close();
			 Account.deleteSessions();

			 if(!Account.sessionStart())throw new Exception("Error aliniciar sesion");
			 return true;
        	}
        	else return false;

	}


	 public static boolean preSessionLogin(String token) throws Exception
         {

                String presession=Account.hashPass(token);
                String sqlLogin = "SELECT UserID from PreSessions where SessionToken=?";
                Connection con = Account.getConnection();

                PreparedStatement ps = con.prepareStatement(sqlLogin);
                ps.setString(1,presession);

                ResultSet rs = ps.executeQuery();

                if(rs.next())
                {
                         Account.__uid=rs.getString("UserID");
                         con.close();
                         Account.deleteSessions();

                         if(!Account.sessionStart())throw new Exception("Error aliniciar sesion");
                         return true;
                }
                else return false;

        }
	


	public static boolean logout()
	{
		
		try
                {
			Account.deleteSessions();			
			File session = new File(Account.__sessiondir+"crypto.session");
			session.delete();

			return true;

                }catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}	
	}

	public static boolean checkSession()
	{
				
		try
		{
			String session= new String(Files.readAllBytes(new File(Account.__sessiondir+"crypto.session").toPath()));
		
			String sqlCheck = "SELECT UserID from Sessions where SessionID=?";
                	Connection con = Account.getConnection();

                	PreparedStatement ps = con.prepareStatement(sqlCheck);
                	ps.setString(1,session);

                	ResultSet rs = ps.executeQuery();

                	if(rs.next())
                	{
                         	Account.__uid=rs.getString("UserID");
                         	con.close();
				return true;
                	}
                	else return false;

		}catch(Exception e)
		{
			return false;
		}
		
	}

	
	public  static String getID()
	{
		return Account.__uid;
	}


	public static boolean sessionStart()
	{

		try
		{
			SimpleDateFormat dateFormat = new SimpleDateFormat("ddMMyyyyHHmmss");
			String date  = dateFormat.format(new Date());
			String session = Account.hashPass(date);

	                String sqlInsertSession = "INSERT INTO Sessions (UserID, SessionID) values (?,?);";
        	        Connection con = Account.getConnection();
                	PreparedStatement ps = con.prepareStatement(sqlInsertSession);
	                ps.setString(1,Account.__uid);
        	        ps.setString(2,session);

                	ps.executeUpdate();
	                con.close();
			
			OutputStream out = new FileOutputStream(new File(Account.__sessiondir+"crypto.session"));
			out.write(session.getBytes());
			out.close();

			return true;

		}catch(Exception e)
		{
			Account.logout();
			return false;
		}
	}


	public static boolean vincular(String sign)
	{
		try
		{
			String presession=Account.hashPass(sign);
			String sqlInsertPreSession = "INSERT INTO PreSessions (UserID, SessionToken) values (?,?);";
                        Connection con = Account.getConnection();
                        PreparedStatement ps = con.prepareStatement(sqlInsertPreSession);
                        ps.setString(1,Account.__uid);
                        ps.setString(2,presession);

			ps.executeUpdate();
                        con.close();

			return true;
	
				
		}catch(Exception e)
		{
			return false;			
		}


	}


	public static boolean  owned(String passwd) throws Exception
	{
		System.out.println("Verificando password...");
		String phash = Account.hashPassSHA1(passwd);
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

		}

		return false;
	} 


	private static String hashPassSHA1( String pass) throws Exception
	{
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] array = md.digest(pass.getBytes());
            StringBuffer sb = new StringBuffer();

            	for (int i = 0; i < array.length; ++i) 
		   sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
            
            return sb.toString();
    
	}

	
	 private static String hashPass( String pass) throws Exception
        {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] array = md.digest(pass.getBytes());
            StringBuffer sb = new StringBuffer();

                for (int i = 0; i < array.length; ++i)
                   sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));

            return sb.toString();

        }

	


	private static Connection getConnection() throws Exception
	{
		Account.loadConf();
		Class.forName("com.mysql.jdbc.Driver");
		Connection connection =DriverManager.getConnection("jdbc:mysql://"+Account.__dbhost+"/"+Account.__dbname+"?user="+Account.__dbuser+"&password="+Account.__dbpasswd);
		if(connection==null) throw new Exception("Error de  conexion");
		return connection;
	}
	
	 private static void loadConf() throws Exception
        {
                 Properties p = new Properties();
                 p.load(new FileInputStream("crypto.ini"));
                 Account.__dbhost=p.getProperty("dbhost");
		 Account.__dbname=p.getProperty("dbname");
		 Account.__dbuser=p.getProperty("dbuser");
		 Account.__dbpasswd=p.getProperty("dbpassword");
		 Account.__sessiondir=p.getProperty("sessiondir");
        }


	private static void deleteSessions() throws Exception
	{
		String sqlDelete = "DELETE from Sessions where UserID=?";
                Connection con = Account.getConnection();

                PreparedStatement ps = con.prepareStatement(sqlDelete);
                ps.setString(1,Account.__uid);

                ps.executeUpdate();		
	}

		
}
