import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.codec.binary.Base64;


class Crypto
{
	public static void parse( String args[])
  	{
                
		try
		{
		
			if(args.length==0) Crypto.printHelp();
                	else
                	{
                        	switch(args[0])
                        	{
                                	case("-r"):
	                                case("register"):Crypto.register();
        	                        break;

                	                case("-l"):
                        	        case("login"):Crypto.login();
                                	break;

		                        case("-s"):
                	                case("sign"):Crypto.sign(args[1],args[2]);
                        	        break;

                                	case("-v"):
	                                case("verify"):Crypto.verify(args[1],args[2],args[3]);
		
                	                case("-e"):
                        	        case("encrypt"):Crypto.encrypt(args[1]);
                                	break;

	                                case("-d"):
        	                        case("decrypt"):Crypto.decrypt(args[1],args[2]);
	
        	                        case("-h"):
                	                case("--help"):
                        	        default: Crypto.printHelp(); 

		
                	        }

                	}

		}catch(Exception e)
		{
			e.printStackTrace();
		}


  	}

	public static void printHelp()
  	{
                        System.out.println("Usage: java -jar crypt.jar [options][<input files>]");
                        System.out.println("Opptions:");
                        System.out.println("-r, register        			register new user");
                        System.out.println("-l, login           			user login");
			System.out.println("-o, login           			user logout");
                        System.out.println("-s, sign  	<privatekey,document> 		sign the input file");
                        System.out.println("-v, verify  <publickey,signature,document>	verify sign");
                        System.out.println("-e, encrypt <>       			encript the input file");
                        System.out.println("-d, decrypt <>        			decrypt the input file");

  	}
	

	public static void register() throws Exception
	{

	}


	public static void login()
	{
	
	}	



	public static void sign(String fileKey,String file) throws Exception
	{
		PrivateKey privada=Crypto.getPrivateKey(fileKey);
		byte[] document= Crypto.readFile(file);

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privada);
		signature.update(document);
		
		String signame=file.substring(0,file.lastIndexOf('.'))+".sign";

		Crypto.saveFile(signame,signature.sign());		 	

		System.out.println("Archivo firmado ok!!");
	}
	

	public static void verify(String fileKey, String fileSign, String file) throws Exception
	{
		
		PublicKey publica=Crypto.getPublicKey(fileKey);
		byte[] document = Crypto.readFile(file);
		byte[] signature= Crypto.readFile(fileSign); 
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publica);
		sig.update(document);
		
		if(sig.verify(signature))
		System.out.println("Verification OK");
		else
		System.out.println("Verification Failed");
	}
	

	public static void encrypt(String file)
	{
	}

	public static void decrypt(String synKey, String file)
	{
	}


	//////////////////////////////////////////////////////////////////////


	private static byte[] readFile(String filename) throws Exception
	{
		byte[] Bytes = Files.readAllBytes(new File(filename).toPath());
		return Bytes;
	}

	private static void saveFile(String filename,byte[] data) throws Exception
	{
		Path path= Paths.get(filename);
		Files.write(path,data);		
	}

	private static PrivateKey getPrivateKey(String filename) throws Exception
	{
		byte[] Key=Crypto.readFile(filename);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Key);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
		
	}

	private static PublicKey getPublicKey(String filename) throws Exception
	{
                byte[] key = Crypto.readFile(filename);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(spec);
	}
		
}
