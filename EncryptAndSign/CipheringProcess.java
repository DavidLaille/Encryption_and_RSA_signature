package EncryptAndSign;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

//Class CipheringProcess
//This process take place in computer A
//This computer A will send the encrypted message to a computer B
//A and B own each one a pair of RSA private and public keys
//The AES secret key will be generated randomly and associated with a initialization vector
//The AES key will be encrypted with B's public key
//The AES encrypted key will be saved in a file with extension ".enc"
//The signature will be done with A's private key

public class CipheringProcess {

	//Method signFile : allow the signature of a file
	//Parameters : Cipher object, Signature object, InputStream, OutputStream
	//Cipher : used to encrypt the file
	//Signature : used to sign the message
	//InputStream : to read the message from this file
	//OutputStream : to write the output	
	
	static private void signFile(Cipher ci,Signature sign,InputStream in,OutputStream out)
		    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.security.SignatureException,
		           java.io.IOException
		{
		    byte[] ibuf = new byte[1024];
		    int len;
		    while ((len = in.read(ibuf)) != -1) {
		        sign.update(ibuf, 0, len);
		        byte[] obuf = ci.update(ibuf, 0, len);
		        if ( obuf != null ) out.write(obuf);
		    }
		    byte[] obuf = ci.doFinal();
		    if ( obuf != null ) out.write(obuf);
		}	
	
	//How to use class CipheringProcess: java CipheringProcess args[0] args[1] args[2]
	//args[0] : name of the file containing the A's private key 
	//args[1] : name of the file containing the B's public key
	//args[2] : name of the file we want to cipher with AES 	
	
	public static void main(String[] args) 
			throws 	NoSuchAlgorithmException, InvalidKeySpecException, 
					IllegalBlockSizeException, BadPaddingException, 
					IOException, InvalidKeyException, 
					NoSuchPaddingException, InvalidAlgorithmParameterException, 
					SignatureException 
		{
		
		//Load A's private key and B's public keys
			//System.out.println("1.Test load of the public and private keys");
		
			PrivateKey pvt = null;
		    String pvtKeyFile = args[0];
			{
				byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));
			    PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    pvt = kf.generatePrivate(ks);
			}
			System.out.println("Private key read from " + pvtKeyFile);
			 
			PublicKey pub = null;
		    String pubKeyFile = args[1];
			{
				byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
			    X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    pub = kf.generatePublic(ks);
			}
			System.out.println("Public key read from " + pubKeyFile);
		
		 
		//Generation of the AES secret key
			//System.out.println("2.Test generation of AES key");
			
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128);
			SecretKey skey = kgen.generateKey();
			
			System.out.println("Generation of AES key done.");
	
		//Initialization vector
			//System.out.println("3.Test initialization vector");
			
			byte[] iv = new byte[128/8];
			new SecureRandom().nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			System.out.println("Generation of initialization vector done.");
			
		//Encryption of the AES key with RSA
			//System.out.println("4.Test encryption of the AES key");
			
			String inputFile = args[2];
			FileOutputStream out = new FileOutputStream(inputFile + ".enc");
			{
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");		
			cipher.init(Cipher.ENCRYPT_MODE, pub);	// Encrypt using B's public key
			byte[] b = cipher.doFinal(skey.getEncoded());
			out.write(b);
			}
			 
			out.write(iv);
			
			System.out.println("Encryption of the AES key done with" + pubKeyFile);
			
		//Encryption of the message with AES secret key and signature
			//System.out.println("5.Test encryption of the message");
			
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(pvt); // Sign using A's private key

			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
									
			try (FileInputStream in = new FileInputStream(inputFile)) {
			    signFile(ci, sign, in, out);
			}
			byte[] s = sign.sign();
			out.write(s);
			out.close();

			System.out.println("Encryption of the file" + inputFile + " done.");
			System.out.println("Signature of the file " + inputFile + " done with " + pvtKeyFile);			
			
			//System.out.println("6.Test program go to the end");
	}
	
}
