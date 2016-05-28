import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by boliveira on 5/28/16.
 */

public class Security
{

    public byte[] loadFile(String nickname)
    {
        byte[] keyBytes = null;

        try
        {
            File f = new File( nickname );
            FileInputStream fs = new FileInputStream(f);
            DataInputStream ds = new DataInputStream(fs);
            keyBytes = new byte[(int)f.length()];
            ds.readFully(keyBytes);
            ds.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return keyBytes;
    }

    public PrivateKey getPrivateKey( String nickname )
    {
        try {
            String file = "keys/" + nickname + ".private";
            byte key[] = loadFile(file);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey getPublicKey(String nickname )
    {
        try {
            String file = "keys/" + nickname + ".public";
            byte key[] = loadFile(file);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

}
