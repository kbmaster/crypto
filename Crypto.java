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
import java.security.cert.CertificateFactory;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.security.SecureRandom;
import java.security.KeyPair;

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

					case("-o"):
                                        case("logout"):Crypto.logout();
                                        break;

                	                case("-l"):
                        	        case("login"):Crypto.login();
                                	break;
					
					case("-lci"):
                                        case("loginci"):Crypto.loginCI();
                                        break;
		                        
					case("-s"):
                	                case("sign"):Crypto.sign(args[1]);
                        	        break;

					case("-sci"):
                                        case("signci"):Crypto.signCI(args[1]);
                                        break;

                                	case("-v"):
	                                case("verify"):Crypto.verify(args[1],args[2],args[3]);
					break;

                	                case("-e"):
                        	        case("encrypt"):Crypto.encrypt(args[1]);
                                	break;

	                                case("-d"):
        	                        case("decrypt"):Crypto.decrypt(args[1]);
					break;

        	                        case("-h"):
                	                case("--help"):
                        	        default: Crypto.printHelp(); 
		
                	        }

                	}


  	}

	private static void printHelp()
  	{
			System.out.println("Usage: java -jar crypt.jar [opciones][<archivos>]");
                        System.out.println("Opptions:");
                        System.out.println("-r,register                                 registrar nuevo usuario");
                        System.out.println("-l,login                                    login de usuario");
			System.out.println("-lci,loginci                                login con cedula");
			System.out.println("-o,logout                                   logout de usuario");
                        
			System.out.println("-s,sign     <documento>                     firma el documento");
			System.out.println("-sci,signci <documento>                     firma el documento con cedula");
                        System.out.println("-v,verify   <certificado,firma,documento>   verifica la firma");
                        
			System.out.println("-e,encrypt  <documento>                     encripta el documento");
                        System.out.println("-d,decrypt  <documento>                     desencripta el documento");
  	}

	

	private static void register() throws Exception
	{
                
		System.out.println("Registro de usuario");
		Scanner inputScanner = new Scanner(System.in);
                System.out.print("Usuario: ");
                String user=inputScanner.next();

                //solicito ingreso de password con confirmacion
                String passwd=Crypto.confirmPassword();
		
		//check owned passwords
		if(Account.owned(passwd)) throw new Exception("Tu password no es muy seguro; has un mejor intento ;)");
				
		if(!Account.register(user,passwd)) throw new Exception("Error en registro");
		
		String UID=Account.getID();
		Keys.genPKI(UID,passwd);
		
		System.out.println("Registro exitoso");
	}

	private static void logout() throws Exception
	{
		Crypto.checkSession();
		if(!Account.logout()) throw new Exception("Error al finalizar sesion");
		System.out.println("Sesion finalizada correctamente");
	}	


	private static void login() throws Exception 
	{
		System.out.println("Login de usuario");
		Scanner inputScanner = new Scanner(System.in);
                System.out.print("Usuario: ");
                String user=inputScanner.next();

                System.out.print("Password:");
                String passwd= Crypto.readPin();

		if(!Account.login(user,passwd)) throw new Exception("Credenciales invalidas");
		
		System.out.println("Autenticacion completa");
			
	}	


	private static void loginCI() throws Exception
	{
		System.out.print("Ingrese PIN:");
		String PIN= Crypto.readPin();
		if(!APDU.verifyPIN(PIN)) throw new Exception("Pin incorrecto");

		//init session
		//Account.sessionStart();
		System.out.println("Autenticacion completa");
		
	}

	
	private static void signCI(String file) throws Exception
	{		
		System.out.print("Ingrese PIN:");
		String PIN = Crypto.readPin();
		if(!APDU.verifyPIN(PIN)) throw new Exception("Pin incorrecto");

                byte[] document= Crypto.readFile(file);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                String hash = APDU.byteArrayToHex(md.digest(document));

		String sign =  APDU.sign(hash);
		String cert= APDU.getCertificate();
		
		String signame=file+".ci.sgn";
		String certname=file+".ci.crt";

                Crypto.saveFile(signame, APDU.hexStringToByteArray(sign));
                Crypto.saveFile(certname,cert.getBytes());		

		System.out.println("Firma "+signame+" generada exitosamente");
		System.out.println("Certificado "+certname+"generado exitosamente");
	}	



	private  static void sign(String file) throws Exception
        {
                Crypto.checkSession();

		String uid=Account.getID();
		String password=readPassword();

                PrivateKey privada= Keys.getPrivate(uid,password);
                byte[] document= Crypto.readFile(file);

                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privada);
                signature.update(document);
		X509Certificate cert = Keys.getCertificate(uid);
                
		String signame=file+".sgn";
		String certname=file+".crt";

		Crypto.saveFile(signame,signature.sign());
		Crypto.saveFile(certname,cert.getEncoded());

                System.out.println("Firma "+signame+" generada exitosamente");
		System.out.println("Certificado "+certname+"generado exitosamente");
        }



	private static void verifyCI(String fileKey, String fileSign, String file) throws Exception
	{
                Crypto.checkSession();

                System.out.print("Ingrese PIN:");
                String PIN = Crypto.readPin();
                if(!APDU.verifyPIN(PIN)) throw new Exception("Pin incorrecto");	

		byte[] document = Crypto.readFile(file);
                byte[] signature= Crypto.readFile(fileSign);		
		
		//obtener la clave publica del certificado
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream certificado_b64 = new ByteArrayInputStream(APDU.hexStringToByteArray(APDU.getCertificate()));
		X509Certificate certificado = (X509Certificate) cf.generateCertificate(certificado_b64);
		PublicKey publica=certificado.getPublicKey();
 
		//desencripto la firma
		Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decrypt.init(Cipher.DECRYPT_MODE, publica);
		String decryptedMessage = APDU.byteArrayToHex(decrypt.doFinal(signature));		

		//calculo el hash del documento
		MessageDigest md = MessageDigest.getInstance("SHA-256");
                String hash = APDU.byteArrayToHex(md.digest(document));

		if(decryptedMessage.equals(hash))
                System.out.println("Verification OK");
                else
                System.out.println("Verification Failed");
	}



	private static void verify(String fileKey, String fileSign, String file) throws Exception
	{

		PublicKey publica=Crypto.getPublicKey(fileKey);
		byte[] document = Crypto.readFile(file);
		byte[] signature= Crypto.readFile(fileSign); 
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publica);
		sig.update(document);
		
		if(sig.verify(signature))
		System.out.println("Verificacion OK");
		else
		System.out.println("Fallo en verificacion");
	}
	

	private static void encrypt(String file) throws Exception
        {
                Crypto.checkSession();
                
		//solicito ingreso de password con confirmacion
		String passwd=Crypto.confirmPassword();

                byte[] document=Crypto.readFile(file);

		SecretKey aeskey = Keys.genAES();
		
		Cipher encryptCipher = Cipher.getInstance("AES");
                encryptCipher.init(Cipher.ENCRYPT_MODE, aeskey);

                byte[] encryptedBytes = encryptCipher.doFinal(document);
                String filename=file+".aes";

		//save to keystore
		MessageDigest dg = MessageDigest.getInstance("SHA-256");
		String alias= new String(dg.digest(encryptedBytes));
		Keys.save(alias,aeskey,passwd);
		
                Crypto.saveFile(filename,encryptedBytes);
                System.out.println("File "+filename+" encripted Ok.");
        }


        private static void decrypt(String file) throws Exception
        {
                Crypto.checkSession();
		//solicito ingreso de password con confirmacion
                String passwd=Crypto.confirmPassword();

                byte[] cryptodoc=Crypto.readFile(file);

		//read from keystore
		//save to keystore
                MessageDigest dg = MessageDigest.getInstance("SHA-256");
                String alias= new String(dg.digest(cryptodoc));
                SecretKey aeskey = Keys.read(alias,passwd);

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
		FileInputStream cert = new FileInputStream(filename);
		CertificateFactory f = CertificateFactory.getInstance("X.509");	
		X509Certificate x509 = (X509Certificate) f.generateCertificate(cert);
		return x509.getPublicKey();
	}

	 private static String readPin()
        {
               Console console = System.console();
               char[] pinChars = console.readPassword();

               return new String(pinChars);

        }

	private static String confirmPassword() throws Exception
	{
		System.out.print("Password:");
                String passwd= Crypto.readPin();

                System.out.print("Repetir Password:");
                String passwd2= Crypto.readPin();

                if(!passwd.equals(passwd2)) throw new Exception("Los passwords no coinciden");

		return passwd; 
	}

	private static String readPassword()
	{
		System.out.print("Password:");
                String passwd= Crypto.readPin();
		
		return passwd;
	}


        private static  void checkSession() throws Exception
        {
                if(!Account.checkSession()) throw new Exception("Login requerido");
        }		
}
