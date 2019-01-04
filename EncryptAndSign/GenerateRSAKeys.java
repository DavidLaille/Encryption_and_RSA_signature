package EncryptAndSign;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

//Generate a pair of RSA private and public keys.
//These keys are saved in files with the extensions ".private" and ".public"
//They are saved as binary data

public class GenerateRSAKeys {

	//How to use : java CipheringProcess args[0] args[1]
	//args[0] : name of the file where the private RSA key will be saved
	//args[1] : name of the file where the public RSA key will be saved
	
	public static void main(String[] args) 
			throws FileNotFoundException, IOException, 
			NoSuchAlgorithmException 
		{
		
		//Generating the RSA pair of keys
			//System.out.println("1.Test generation of RSA pair of key"); 
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			
			System.out.println("Generation of the pair of keys done.");
			 
		//Saving the pair of key
			//System.out.println("2.Test backup of RSA pair of key"); 
			
			String fileBase = args[0];
			try (FileOutputStream out = new FileOutputStream(fileBase   + ".private")) {
			     out.write(kp.getPrivate().getEncoded());
			}			
				
			try (FileOutputStream out = new FileOutputStream(fileBase   + ".public")) {
			     out.write(kp.getPublic().getEncoded());
			}
			
			System.out.println("Private key saved in " + fileBase + ".private");
			System.out.println("Public key saved in " + fileBase + ".public");
		
		}
}
