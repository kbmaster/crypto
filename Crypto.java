import java.io.*;
import java.nio.*;
import java.security.*;

class Crypto
{
	public static void parse( String args[])
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
                                case("verify"):Crypto.verify(args[1],args[2]);

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


  	}

	public static void printHelp()
  	{
                        System.out.println("Usage: java -jar crypt.jar [options]");
                        System.out.println("Opptions:");
                        System.out.println("-r, register        register new user");
                        System.out.println("-l, login           user login");
                        System.out.println("-s, sign            sign the input file, return file.sign");
                        System.out.println("-v, verify          verify sign ");
                        System.out.println("-e, encrypt         encript input file");
                        System.out.println("-d, decrypt         decrypt input file");

  	}
	

	public static void register(){System.out.println("register");}
	public static void login(){System.out.println("login");}
	
	public static void sign(String fileKey,String file)	
	{
		
		/*PivateKey privada=Crypto.getPrivateKey(filekey);
		byte[] document= Crypto.readFile(file);

		Signature signature = Signature.getInstance("SHA2withRSA");
		signaturr.initSing(privada);
		signature.update(document);
		
		String signame=file.substring(0,file.lastIndexOf('.'));

		Crypto.saveFile(signame,signature.sign());		 		*/

		System.out.println("Archivo firmado ok!!");
	}
	

	public static void verify(String fileKey,String file){System.out.println("verify");}
	public static void encrypt(String file){System.out.println("encrypt");}
	public static void decrypt(String synKey, String file){System.out.println("decrypt");}


	private byte[] readFile(String filename)
	{
		/*byte[] Bytes = Files.readAllBytes(new File(filename).toPath());
		return Bytes;*/

		return null;
	}

	private void saveFile(String filename,byte[] data)
	{
		
	}

	private PrivateKey getPrivateKey(String filename)
	{
		/*byte[] Key= Crypto.readFile(filename);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Key);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);*/

		return null;
	}
		
}
