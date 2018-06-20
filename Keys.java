import java.util.Date;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

import java.util.*;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.*;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyPairGenerator;
import javax.security.auth.x500.X500Principal;


import javax.crypto.*;
import javax.crypto.KeyGenerator;


class Keys
{
	static private String __ksdir="./keys/keystore.ks";
	static private String __kspassword="2E868F987DB3D6A693192C3CD71A991F";	

	static public SecretKey genAES() throws Exception
	{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); 
		return  keyGen.generateKey();
	}

	
	static public void genPKI(String uid, String password) throws Exception
	{
		System.out.println("Creando Certificados ...");
		Security.addProvider(new BouncyCastleProvider());
		
		// generate a key pair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
                keyPairGenerator.initialize(2048, new SecureRandom());
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                PrivateKey privada = keyPair.getPrivate();
		X509Certificate certificado= Keys.genX509(keyPair);	
		X509Certificate [] chain={certificado};

		//salvar en keystore
		KeyStore ks = Keys.load();
                KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privada,chain);
                KeyStore.ProtectionParameter entryPassword =  new KeyStore.PasswordProtection(password.toCharArray());
                ks.setEntry("PRIV-"+uid,privateKeyEntry,entryPassword);

		//la publica se salva siempre con el mismo password choto
                KeyStore.TrustedCertificateEntry certificateEntry = new KeyStore.TrustedCertificateEntry(certificado);
                ks.setEntry("PUB-"+uid,certificateEntry,null);

		FileOutputStream keyStoreOutputStream = new FileOutputStream(Keys.__ksdir);
                ks.store(keyStoreOutputStream,Keys.__kspassword.toCharArray()); 
		
	}
	
	static public PrivateKey getPrivate(String uid, String password) throws Exception
	{
		try
		{
			KeyStore ks = Keys.load();
                	KeyStore.ProtectionParameter entryPassword =  new KeyStore.PasswordProtection(password.toCharArray());
	                KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("PRIV-"+uid,entryPassword);
	                return  keyEntry.getPrivateKey();				
			
		}catch (Exception e)
		{
			throw new Exception("Password invalido");
		}

	}

	static public X509Certificate getCertificate(String uid) throws Exception
	{
		KeyStore ks = Keys.load();
                KeyStore.TrustedCertificateEntry keyEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry("PUB-"+uid,null);

                return (X509Certificate) keyEntry.getTrustedCertificate();
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
		Keys.loadConf();
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

	private static void loadConf() throws Exception
	{
		 Properties p = new Properties();
      		 p.load(new FileInputStream("crypto.ini"));
		 Keys.__ksdir=p.getProperty("keystore");
	}

	private static X509Certificate  genX509(KeyPair keyPair) throws Exception
	{
		//Security.addProvider(new BouncyCastleProvider());
		// generate a key pair
		//KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		//keyPairGenerator.initialize(2048, new SecureRandom());
		//KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// build a certificate generator
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("cn=example");

		// add some options
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setSubjectDN(new X509Name("dc=name"));
		certGen.setIssuerDN(dnName); // use the same
		// yesterday
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
		// in 2 years
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new 
		ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
		
		// finally, sign the certificate with the private key of the same KeyPair		
		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
		return cert;

	}



}
