import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.KeyGenerator;


class Keys
{
	static private String __ksdir="./keys/keystore.ks";
	static private String __kspassword="somelargetext";	

	static public SecretKey genAES() throws Exception
	{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); 
		return  keyGen.generateKey();
	}

	
	static public void save(String alias,SecretKey key,String password) throws Exception
	{
		KeyStore ks = Keys.load();
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);
		KeyStore.ProtectionParameter entryPassword =  new KeyStore.PasswordProtection(password.toCharArray());
		ks.setEntry(alias,secretKeyEntry,entryPassword);	

		FileOutputStream keyStoreOutputStream = new FileOutputStream(Keys.__ksdir);
		ks.store(keyStoreOutputStream,Keys.__kspassword.toCharArray());		
		
	}
	
	static public SecretKey  read(String alias,String password) throws Exception
	{
		KeyStore ks = Keys.load();
		KeyStore.ProtectionParameter entryPassword =  new KeyStore.PasswordProtection(password.toCharArray());
		KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, entryPassword);
		
		return  keyEntry.getSecretKey();
	}

	private static KeyStore load() throws Exception
	{
		KeyStore ks = KeyStore.getInstance("PKCS12");
		
		//tata de cargar el keystore
		try
		{
			InputStream keyStoreData = new FileInputStream(Keys.__ksdir);
			ks.load(keyStoreData,Keys.__kspassword.toCharArray());

		}catch(IOException e)//si falla es prque no existe => lo crea
		{
			ks.load(null,Keys.__kspassword.toCharArray());			
			FileOutputStream keyStoreOutputStream = new FileOutputStream(Keys.__ksdir);
			ks.store(keyStoreOutputStream,Keys.__kspassword.toCharArray());
		}
		
		return ks;
	}



}
