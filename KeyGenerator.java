import java.io.FileOutputStream;
import java.security.*;

/**
 * This class generates unique keys for users based on the RSA algorithm with 1024 bits encryption.
 */

public class KeyGenerator
{
 	public static void generateKey(String username){
 		
 		try{
			/* Random number generator - Seed */
			SecureRandom random = SecureRandom.getInstanceStrong();

			/* Generates secret keys for RSA algorithm */
	 		KeyPairGenerator generateKey = KeyPairGenerator.getInstance("RSA");
	 		generateKey.initialize(1024,random);

			/* Use KeyPairGenerator to generate keypair */
	 		KeyPair pair = generateKey.generateKeyPair();
	 		PrivateKey priv = pair.getPrivate();
	 		PublicKey pub = pair.getPublic();

	 		/* Writing private key to a file */
	 		byte[] keyPriv = priv.getEncoded();
	 		FileOutputStream privKeyWriting = new FileOutputStream("keys/" + username + ".private");
	 		privKeyWriting.write(keyPriv);
	 		privKeyWriting.close();

	 		/* Writing public key to a file */
	 		byte[] keyPub = pub.getEncoded();
	 		FileOutputStream pubKeyWriting = new FileOutputStream("keys/" + username + ".public");
	 		pubKeyWriting.write(keyPub);
	 		pubKeyWriting.close();

	 	}catch(Exception e){
	 		e.printStackTrace();
	 	}
 	}

 	public static void main(String args[])
	{
		generateKey("server");
		generateKey("bryan");
		generateKey("pedro");
 	}
}