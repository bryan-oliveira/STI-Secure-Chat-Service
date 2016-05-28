import java.io.FileOutputStream;
import java.security.*;

public class KeyGenerator
{
 	public static void generateKey(String keyname){
 		
 		try{
	 		// Generates secret keys for DH algorithm 
	 		KeyPairGenerator generateKey = KeyPairGenerator.getInstance("DH");
	 		// Random number generator 
	 		SecureRandom random = new SecureRandom();
	 		byte bytes[] = new byte[20];
	 		random.nextBytes(bytes);
	 		generateKey.initialize(1024,random);

	 		KeyPair pair = generateKey.generateKeyPair();
	 		PrivateKey priv = pair.getPrivate();
	 		PublicKey pub = pair.getPublic();

	 		// Writing private key to a file
	 		byte[] keyPriv = priv.getEncoded();
	 		FileOutputStream privKeyWriting = new FileOutputStream("keys/" + keyname + ".public");
	 		privKeyWriting.write(keyPriv);
	 		privKeyWriting.close();

	 		// Writing public key to a file
	 		byte[] keyPub = pub.getEncoded();
	 		FileOutputStream pubKeyWriting = new FileOutputStream("keys/" + keyname + ".private");
	 		pubKeyWriting.write(keyPub);
	 		pubKeyWriting.close();
	 	}catch(Exception e){
	 		e.printStackTrace();
	 	}
 	}

 	public static void main(String args[])
	{
		//generateKey("server");
		generateKey("bryan");
		generateKey("pedro");
 	}
}