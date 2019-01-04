package EncryptAndSign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//Class DecipheringProcess
//This process take place in computer B
//This computer B receive the encrypted message from computer A
//A and B own each one a pair of RSA private and public keys
//AES secret key is first decrypted with B's private key
//Then, the message is decrypted with the AES key
//Finally, the signature is decrypted with A's public key
//The signature will be compared with the initial signature (present in the file)

public class DecipheringProcess {

	//Method authFile : verifies the signature of the decrypted message
	//Parameters : Cipher object, Signature object, InputStream, OutputStream
	//Cipher : used to decrypt the file
	//Signature : used to sign the file; the signed file will be compared to the original
	
	static private void authFile(Cipher ci,Signature ver,InputStream in,OutputStream out,long dataLen)
		    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.security.SignatureException,
		           java.io.IOException
		{
		    byte[] ibuf = new byte[1024];
		    while (dataLen > 0) {
		        int max = (int)(dataLen > ibuf.length ? ibuf.length : dataLen);
		        int len = in.read(ibuf, 0, max);
		        if ( len < 0 ) throw new java.io.IOException("Insufficient data");
		        dataLen -= len;
		        byte[] obuf = ci.update(ibuf, 0, len);
		        if ( obuf != null ) {
		            out.write(obuf);
		            ver.update(obuf);
		        }
		    }
		    byte[] obuf = ci.doFinal();
		    if ( obuf != null ) {
		        out.write(obuf);
		        ver.update(obuf);
		    }
		}
	
	//How to use class DecipheringProcess: java DeipheringProcess args[0] args[1] args[2]
	//args[0] : name of the file containing the A's public key 
	//args[1] : name of the file containing the B's private key
	//args[2] : name of the file we want to decipher with AES 
	
	public static void main(String[] args) 
			throws 	FileNotFoundException, 
					IOException, InvalidKeySpecException,
					NoSuchAlgorithmException, IllegalBlockSizeException, 
					BadPaddingException, NoSuchPaddingException, 
					InvalidKeyException, InvalidAlgorithmParameterException,
					SignatureException 
		{
		
		//Load A's public key and B's private key
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
		
		//Decrypting the AES key
			//System.out.println("2.Test decryption of AES key");
			
			String inputFile = args[2];
			
			//Computing the length of the encrypted file
			long dataLen = new File(inputFile ).length()
				    - 256       // AES Key
				    - 16        // IV
				    - 256;      // Signature
			
			FileInputStream in = new FileInputStream(inputFile);
			SecretKeySpec skey = null;
			{
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");	
			cipher.init(Cipher.DECRYPT_MODE, pvt); // B's private key here
			byte[] b = new byte[256];	
			in.read(b);
			byte[] keyb = cipher.doFinal(b);
			skey = new SecretKeySpec(keyb, "AES");
			}
			
			System.out.println("Decryption of the AES secret key done with " + pvtKeyFile);
			
		//Loading the initialization vector
			//System.out.println("3.Test load of initialization vector");
			
			byte[] iv = new byte[128/8];
			in.read(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			System.out.println("Initialization vector read.");
			
		//Decrypting the message and verifying the signature
			//System.out.println("4.Test decryption of the message and verification of the signature");
			
			Signature ver = Signature.getInstance("SHA256withRSA");
			ver.initVerify(pub); // Using B's public key
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
			try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
			    authFile(ci, ver, in, out, dataLen);				
			}
			
			System.out.println("Decryption of the file " + inputFile + " done.");
			System.out.println("Signature of the file " + inputFile + " checked");			
			
			byte[] s = new byte[256];
			int len = in.read(s);
			if ( ! ver.verify(s) ) {
				System.out.println("Signature not valid: ");
			}
			
			System.out.println("The decrypted message is located in the file " + inputFile + ".ver");;

	}
}