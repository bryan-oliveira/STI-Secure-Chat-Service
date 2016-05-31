import javax.crypto.*;
import javax.crypto.KeyGenerator;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * Created by boliveira on 5/28/16.
 * Defines Security functionality pertaining to public/private key administration.
 */

public class Security
{
    /* Public/Private key path */
    private static final String KEY_PATH = "keys/";
    private static final String PUBLIC_KEY_EXTENSION = ".public";
    private static final String PRIVATE_KEY_EXTENSION = ".private";

    private byte[] loadFile(String filename)
    {
        byte[] keyBytes = null;

        try
        {
            File f = new File(filename);
            FileInputStream fs = new FileInputStream(f);
            DataInputStream ds = new DataInputStream(fs);
            keyBytes = new byte[(int)f.length()];
            ds.readFully(keyBytes);
            ds.close();

        } catch (IOException e) { e.printStackTrace(); }
        return keyBytes;
    }

    public PublicKey getPublicKeyFromFile(String nickname ) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte [] key = loadFile(KEY_PATH + nickname + PUBLIC_KEY_EXTENSION);
        System.out.println(nickname + " public key len:" +key.length);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        PublicKey pk = KeyFactory.getInstance("DSA").generatePublic(spec);
        return pk;
    }

    public PrivateKey getPrivateKeyFromFile(String nickname ) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte [] key = loadFile(KEY_PATH + nickname + PRIVATE_KEY_EXTENSION);
        KeyFactory kf = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        PrivateKey pk = kf.generatePrivate(spec);
        return pk;
    }

    private SecureRandom generateSecureRandomSeed() throws NoSuchProviderException, NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        return random;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        /* Generates secret keys for DSA algorithm */
        KeyPairGenerator generateKey = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = generateSecureRandomSeed();
        generateKey.initialize(1024,random);

        KeyPair pair = generateKey.generateKeyPair();
        //PrivateKey priv = pair.getPrivate();
        //PublicKey pub = pair.getPublic();

        return pair;
    }

    public SecretKey generateSymetricKey()
    {
        try {
            KeyGenerator kg = null;
            kg = KeyGenerator.getInstance("AES");
            SecureRandom random = generateSecureRandomSeed();
            kg.init(256,random);
            return kg.generateKey();

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean saveKeyPairToFile(KeyPair pair, String username)
    {
        try
        {
            PublicKey pub = pair.getPublic();
            byte[] encodePub = pub.getEncoded();
            FileOutputStream pubFS = new FileOutputStream(KEY_PATH + username + PUBLIC_KEY_EXTENSION);
            pubFS.write(encodePub);
            pubFS.close();

            PrivateKey priv = pair.getPrivate();
            byte[] encodePriv = priv.getEncoded();
            FileOutputStream privFS = new FileOutputStream(KEY_PATH + username + PRIVATE_KEY_EXTENSION);
            privFS.write(encodePriv);
            privFS.close();

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public byte[] encryptMessageSym(SecretKey key, byte[] text)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(text);

        } catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException |
                NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] encryptMessage(PublicKey key, byte[] text)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(text);

        } catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException |
                NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decryptMessageSym(SecretKey key, byte [] text)
    {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(text);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decryptMessage(PrivateKey key, byte [] text)
    {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(text);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] signMessage( PrivateKey key, byte[] data )
    {
        /* Based on https://docs.oracle.com/javase/tutorial/security/apisign/step3.html */
        try {
            Signature rsa = Signature.getInstance("MD5withRSA");
            rsa.initSign(key);
            rsa.update(data);
            return rsa.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verifyMessageSignature (PublicKey key, byte[] signature, byte[] data)
    {
        /* Based on https://docs.oracle.com/javase/tutorial/security/apisign/vstep4.html */
        try {
            Signature sig = Signature.getInstance("MD5withRSA");
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public PublicKey getPublicKeyFromBytes ( byte[] key)
    {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        PublicKey pk = null;
        try {
            pk = KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return pk;
    }

    public byte[] getBytesFromKeyPair(KeyPair keyPair, String keyType)
    {

        if(keyType.equalsIgnoreCase("public"))
            return keyPair.getPublic().getEncoded();

        if(keyType.equalsIgnoreCase("private"))
            return keyPair.getPrivate().getEncoded();

        return null;
    }

    public byte[] getBytesFromPublicKey(PublicKey key)
    {
        return key.getEncoded();
    }

    public byte[] getBytesFromPrivateKey(PrivateKey key)
    {
        return key.getEncoded();
    }
}
