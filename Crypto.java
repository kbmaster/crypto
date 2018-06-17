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
import java.security.MessageDigest;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Crypto
{
	public static void parse( String args[]) throws Exception
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
					
					case("-lci"):
                                        case("loginci"):Crypto.loginCI();
                                        break;
		                        
					case("-s"):
                	                case("sign"):Crypto.sign(args[1],args[2]);
                        	        break;

					case("-sci"):
                                        case("signci"):Crypto.signCI(args[1]);
                                        break;

                                	case("-v"):
	                                case("verify"):Crypto.verify(args[1],args[2],args[3]);
					break;

                	                case("-e"):
                        	        case("encrypt"):Crypto.encrypt(args[1],args[2]);
                                	break;

	                                case("-d"):
        	                        case("decrypt"):Crypto.decrypt(args[1],args[2]);
					break;
	
        	                        case("-h"):
                	                case("--help"):
                        	        default: Crypto.printHelp(); 
		
                	        }

                	}


  	}

	public static void printHelp()
  	{
                        System.out.println("Usage: java -jar crypt.jar [options][<files>]");
                        System.out.println("Opptions:");
                        System.out.println("-r, register        			register new user");
                        System.out.println("-l, login           			user login");
			System.out.println("-lci, loginci                               user login with ci");
			System.out.println("-o, login           			user logout");
                        System.out.println("-s, sign  	<privatekey,document> 		sign the document");
			System.out.println("-sci, signci<document>			sing the document with ci");
                        System.out.println("-v, verify  <publickey,signature,document>	verify sign");
                        System.out.println("-e, encrypt <symkey,document>		encript the document");
                        System.out.println("-d, decrypt <symkey,document>		decrypt the document");
  	}

	
	private static String readPin()
	{
	       Console console = System.console();
               System.out.print("Ingrese PIN:");
               char[] pinChars = console.readPassword();

               return new String(pinChars);
		
	}
	

	public static void register() throws Exception
	{
		
	}


	public static void login()
	{
	
	}	


	public static void loginCI() throws Exception
	{
		
		String PIN= Crypto.readPin();
		if(!APDU.verifyPIN(PIN)) throw new Exception("Pin incorrecto");

		//init session

		System.out.println("Autenticacion completa");
		
	}

	
	public static void signCI(String file) throws Exception
	{
		String PIN = Crypto.readPin();
		if(!APDU.verifyPIN(PIN)) throw new Exception("Pin incorrecto");

                byte[] document= Crypto.readFile(file);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                String hash = new String(md.digest(document));

		String sign =  APDU.sign(hash);

		String signame=file+".sgn";
                Crypto.saveFile(signame,sign.getBytes());

		System.out.println("Firma "+signame+" generada exitosamente");
	}	



	public static void sign(String fileKey,String file) throws Exception
	{
		PrivateKey privada=Crypto.getPrivateKey(fileKey);
		byte[] document= Crypto.readFile(file);

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privada);
		signature.update(document);
		
		String signame=file+".sgn";

		Crypto.saveFile(signame,signature.sign());		 	
		System.out.println("Firma "+signame+" generada exitosamente");
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
	

	public static void encrypt(String fileKey, String file) throws Exception
	{
		byte[] document=Crypto.readFile(file);
		byte[] key= Crypto.readFile(fileKey);
		
		SecretKey aeskey = new SecretKeySpec(key,"AES");

		Cipher encryptCipher = Cipher.getInstance("AES");
		encryptCipher.init(Cipher.ENCRYPT_MODE, aeskey);
		
		byte[] encryptedBytes = encryptCipher.doFinal(document);
		String filename=file+".aes";
		
		Crypto.saveFile(filename,encryptedBytes);		

		System.out.println("File "+filename+" encripted Ok.");
	}


	public static void decrypt(String fileKey, String file) throws Exception
	{
		byte[] key= Crypto.readFile(fileKey);
                byte[] cryptodoc=Crypto.readFile(file);

		SecretKey aeskey = new SecretKeySpec(key,"AES");

		Cipher decryptCipher = Cipher.getInstance("AES");
    		decryptCipher.init(Cipher.DECRYPT_MODE, aeskey);
				
		byte[] document = decryptCipher.doFinal(cryptodoc); 

		String filename=file.substring(0,file.lastIndexOf('.'));
		Crypto.saveFile(filename,document);

		System.out.println("File "+filename+" decripted Ok.");
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
