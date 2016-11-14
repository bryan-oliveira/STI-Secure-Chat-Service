
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.security.*;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private DataInputStream streamIn   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;

    private Security    security            = null;
    private PublicKey   clientPublicKey     = null;
    private PrivateKey  clientPrivateKey    = null;
    private PublicKey   serverPublicKey     = null;
    private SecretKey   serverSymKey        = null;
    private String      nickname            = null;
    private boolean     renewKeyLease       = false;
    private boolean     secureConnEstablished = false;

    public ChatClient(String serverName, int serverPort, String nickname)
    {
        System.out.println("Establishing connection to server...");
        try
        {
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + serverName + ":" + socket);
            start();

        } catch(UnknownHostException uhe) {
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        } catch(IOException ioexception) {
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[])
    {Decrypted msg with client private key
Signed message
        ChatClient client = null;
        if (args.length != 3)
            System.out.println("Usage: java ChatClient <host> <port> <nickname>");
        else
            // Calls new client { hostname, port, nickname }
            client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
    }

    // Inits new client thread
    public void start() throws IOException, NoSuchProviderException, NoSuchAlgorithmException
    {
        console   = new DataInputStream(System.in);
        streamOut = new DataOutputStream(socket.getOutputStream());
        streamIn = new DataInputStream(socket.getInputStream());

        security  = new Security();
        secureConnEstablished = false;

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    public void run()
    {
       while (thread != null)
       {
           // Sends message from console to server
           String msg = null;
           try {

               msg = console.readLine();

               byte[] msgBytes = msg.getBytes();
               byte[] hash = security.signMessage(clientPrivateKey, msgBytes);

               byte[] msgEncrypted = security.encryptMessageSym(serverSymKey, msgBytes);
               byte[] hashEncrypted = security.encryptMessageSym(serverSymKey, hash);

               sendBytes(msgEncrypted);
               sendBytes(hashEncrypted);
               System.out.println("Sent msg to server");

           } catch (IOException e) {
               e.printStackTrace();
           }
       }
    }
    
    public void handle(byte[] msg, byte[] hash)
    {
        if(new String(msg).equalsIgnoreCase("AUTH_REQUEST_TOKEN"))
        {
            System.out.println("SECURE AUTHORIZATION: Server requested new auth. Renewing keys with server");
            generateKeys();
            secureConnEstablished = secureConnection(nickname);
            return;
        }

        byte[] msgDecrypted = security.decryptMessageSym(serverSymKey, msg);
        System.out.println("Decrypted msg");

        byte[] hashDecrypted = security.decryptMessageSym(serverSymKey, hash);

        boolean verifySignature = security.verifyMessageSignature(serverPublicKey, hashDecrypted, msgDecrypted);
        System.out.println("Msg: " + new StringDecrypted msg with client private key
        Signed message(msgDecrypted));
        System.out.println("Msg is verified:" + verifySignature + "Source: server (public key)");

        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(new String(msgDecrypted));
    }

    // Stops client thread
    public void stop()
    {  
        if (thread != null)
        {  
            thread.stop();  
            thread = null;
        }
        try
        {  
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing thread..."); }
            client.close();  
            client.stop();
    }

    private boolean secureConnection(String nickname) {

        System.out.println("Init Secure connection.");
        try {

            // Send client public key
            byte[] publicKeyBytes = clientPublicKey.getEncoded();
            sendBytes(publicKeyBytes);
            System.out.println("Sent client public key");

            // Get server public key
            byte[] serverPublicKeyBytes = readBDecrypted msg with client private key
Signed messageytes();
            serverPublicKey = security.getPublicKeyFromBytes(serverPublicKeyBytes);
            System.out.println("Got server public key");

            // Get server symmetric key (comes encrypted with my public)
            byte[] serverSymKeyEncrypted = readBytes();
            System.out.println("Got server symmetric key");

            // Decrypt with client private
            byte[] serverSymKeyBytes = security.decryptMessage(clientPrivateKey, serverSymKeyEncrypted);
            System.out.println("Decrypted msg with client private key");

            // Build Symetric key
            serverSymKey = new SecretKeySpec(serverSymKeyBytes, 0, serverSymKeyBytes.length, "AES");

            // Sign message
            String msg = "Msg signed and encrypted with server key.";
            byte[] msgSigned = security.signMessage(clientPrivateKey, msg.getBytes());
            System.out.println("Signed message");

            // Encrypt signed msg with server symetric key and send
            byte[] msgSignatureEncrypted = security.encryptMessageSym(serverSymKey,msgSigned);
            byte[] msgEncrypted = security.encryptMessageSym(serverSymKey, msg.getBytes());

            // Send msg and signed msg
            sendBytes(msgSignatureEncrypted);
            sendBytes(msgEncrypted);

            System.out.println("Sent encrypted signature and encrypted msg");

        } catch ( Exception e) {
            e.printStackTrace();
        }
        System.out.println("End of Secure connection.");
        return true;
    }

    public void generateKeys()
    {
        KeyPair kp = null;
        try {
            kp = security.generateKeyPair();
            clientPublicKey = kp.getPublic();
            clientPrivateKey = kp.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        System.out.println("Generated client keys");
    }

    public byte[] readBytes()
    {
        try
        {
            int lenMsg;
            byte[] message;

            lenMsg = streamIn.readInt();
            message = new byte[lenMsg];

            streamIn.read(message, 0 , lenMsg);

            return message;
        } catch (IOException e) {
            e.printStackTrace();
        }
SECURE AUTHORIZATIO
        return null;
    }

    public void sendBytes(byte[] message)
    {
        try
        {
            streamOut.writeInt(message.length);
            streamOut.write(message);
            streamOut.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private DataInputStream  streamIn = null;

    private Security security = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {
        client   = _client;
        socket   = _socket;
        security = new Security();

        open();
        start();
    }

    public void run() {
        while (true) {
            try {

                byte[] msg = readBytes();

                if( new String(msg).equalsIgnoreCase("AUTH_REQUEST_TOKEN") )
                {
                    client.handle(msg,"".getBytes());
                    continue;
                }

                byte[] hash = readBytes();
               client.handle(msg, hash);

            } catch (Exception ex) {
                System.out.println("Listening error: " + ex.getMessage());
                client.stop();
            }
        }
    }

    public byte[] readBytes()
    {
        try
        {
            int lenMsg;
            byte[] message;

            lenMsg = streamIn.readInt();
            message = new byte[lenMsg];

            streamIn.read(message, 0 , lenMsg);

            return message;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public void open()
    {
        try { streamIn  = new DataInputStream(socket.getInputStream()); }
SECURE AUTHORIZATIO
        catch(IOException ioe)
        {
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }

    public void close()
    {  
        try { if (streamIn != null) streamIn.close(); }

        catch(IOException ioe) { System.out.println("Error closing input stream: " + ioe); }
    }

}

