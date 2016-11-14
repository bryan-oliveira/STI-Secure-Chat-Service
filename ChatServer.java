import javax.crypto.SecretKey;
import java.net.*;
import java.io.*;
import java.security.*;

public class ChatServer implements Runnable
{  
	private ChatServerThread clients[] = new ChatServerThread[20];
	private ServerSocket server_socket = null;
	private Thread thread = null;
	private int clientCount = 0;

	public ChatServer(int port)
	{
		try
		{
			// Binds to port and starts server
			System.out.println("Binding to port " + port);
			server_socket = new ServerSocket(port);
			System.out.println("Server started: " + server_socket);

			start();
		}
		catch(IOException ioexception)
		{
			// Error binding to port
			System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
		}
    }

    public static void main(String args[])
    {
        ChatServer server = null;

        if (args.length != 1)
            System.out.println("Usage: java ChatServer <port>");
        else
            server = new ChatServer(Integer.parseInt(args[0]));
    }

    public void start()
    {
        System.out.println("Start");
        if (thread == null)
        {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }

	public void run()
	{
        while (thread != null)
		{
			try
			{
				// Adds new thread for new client
				System.out.println("Waiting for a client ...");
				addThread(server_socket.accept()); /* Blocks */
			}
			catch(IOException ioexception) { System.out.println("Accept error: " + ioexception); stop(); }
		}
	}

    private void addThread(Socket socket)
    {
        if (clientCount < clients.length)
        {
            // Adds thread for new accepted client
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            try
            {
                clients[clientCount].open();
                clients[clientCount].start();
                clientCount++;
            }
            catch(IOException ioe) { System.out.println("Error opening thread: " + ioe); }
        }
        else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }

	public synchronized void handle(ChatServerThread client, byte[] msg)
	{
        System.out.println("Handle");
        if (msg.equals(".quit"))
			{
				int leaving_id = findClient(client.getID());
				// Client exits
				clients[leaving_id].sendBytes(".quit".getBytes());
				// Notify remaing users
				for (int i = 0; i < clientCount; i++)
                    if (i!=leaving_id)
						clients[i].sendBytes( ("Client " + client.getID() + " exits..").getBytes());
				remove(client.getID());
			}
		else
				// Brodcast message for every other client online
				for (int i = 0; i < clientCount; i++)
                {
                    Security security = new Security();

                    String send = client.getID() + " : " + new String(msg);

                    SecretKey sk = clients[i].getServerSymKey();
                    PrivateKey serverPk = clients[i].getServerPrivateKey();

                    byte[] signature = security.signMessage(serverPk, send.getBytes());

                    byte[] msgEncrypted = security.encryptMessageSym(sk, send.getBytes());

                    byte[] signatureEncrypted = security.encryptMessageSym(sk, signature);

                    clients[i].sendBytes(msgEncrypted);
                    clients[i].sendBytes(signatureEncrypted);
                }

	}

    private int findClient(int ID)
    {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
            if (clients[i].getID() == ID)
                return i;
        return -1;
    }

	public synchronized void remove(int ID)
	{
		int pos = findClient(ID);

		if (pos >= 0)
		{
				// Removes thread for exiting client
				ChatServerThread toTerminate = clients[pos];
				System.out.println("Removing client thread " + ID + " at " + pos);
				if (pos < clientCount-1)
					for (int i = pos+1; i < clientCount; i++)
							clients[i-1] = clients[i];
				clientCount--;

				try { toTerminate.close(); }

				catch(IOException ioe) { System.out.println("Error closing thread: " + ioe); }

				toTerminate.stop();
		}
	}

    public void stop()
    {
        if (thread != null)
        {
            thread.stop();
            thread = null;
        }
    }

}

class ChatServerThread extends Thread
{
    private ChatServer       server    = null;
    private Socket           socket    = null;
    private int              ID        = -1;
    private DataInputStream  streamIn  =  null;
    private DataOutputStream streamOut = null;

    private Security    security            = null;
    private PublicKey   clientPublicKey     = null;
    private PublicKey   serverPublicKey     = null;
    private PrivateKey  serverPrivateKey    = null;
    private SecretKey   serverSymKey        = null;
    private String      nickname            = null;

    private boolean     secureConnectionEstablished = false;
    private long startTime                          = 0;


    public ChatServerThread(ChatServer _server, Socket _socket)
    {
        super();
        System.out.println("Chat server Thread");
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
        security = new Security();
        startTime = System.currentTimeMillis() / 1000;
    }

    private void generateServerKeys()
    {
        KeyPair kp;
        try {
            kp = security.generateKeyPair();
            serverPublicKey = kp.getPublic();
            serverPrivateKey = kp.getPrivate();
            serverSymKey = security.generateSymetricKey();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) { e.printStackTrace(); }
    }

    public boolean secureConnection()
    {
        System.out.println("Init Secure connection.");

        // Get user public key
        byte[] clientPublicKeyBytes = readBytes();
        clientPublicKey = security.getPublicKeyFromBytes(clientPublicKeyBytes);
        System.out.println("Got client public key.");

        // Send server public key
        byte[] serverKeyBytes = serverPublicKey.getEncoded();
        sendBytes(serverKeyBytes);
        System.out.println("Sent server public key");

        // Encrypt server symetric key
        byte[] serverSymKeyBytes = serverSymKey.getEncoded();
        byte[] symKeyEncrypted = security.encryptMessage(clientPublicKey, serverSymKeyBytes);
        sendBytes(symKeyEncrypted);
        System.out.println("Sent server symetric key encrypted with user's public key");

        byte[] msgSignature = readBytes();
        byte[] msgEncrypted = readBytes();
        System.out.println("Received encrypted msg and signature");

        byte[] msgSigDecyphered = security.decryptMessageSym(serverSymKey, msgSignature);
        byte[] msgDecyphered = security.decryptMessageSym(serverSymKey, msgEncrypted);

        System.out.println("Msg from client len:" + msgEncrypted.length + "\nMsg:" + new String(msgDecyphered));

        boolean isSignedByClient = security.verifyMessageSignature(clientPublicKey, msgSigDecyphered, msgDecyphered);
        System.out.println("Is signed by client:" + isSignedByClient);

        System.out.println("Ending Secure connection.");
        return isSignedByClient;
    }

    // Gets id for client
    public int getID()
    {  
        return ID;
    }

    // Runs thread
    public void run()
    {
        System.out.println("Server Thread " + ID + " running.");

        while (true)
        {
            if (!secureConnectionEstablished)
            {
                sendBytes("AUTH_REQUEST_TOKEN".getBytes());
                System.out.println("Generating server keys");
                generateServerKeys();
                secureConnectionEstablished = secureConnection();
            }

            byte[] msg = readBytes();
            byte[] hash = readBytes();
            System.out.println("Read incoming msg and hash");

            byte[] msgDecrypted = security.decryptMessageSym(serverSymKey, msg);
            System.out.println("Decrypted msg");

            byte[] hashDecrypted = security.decryptMessageSym(serverSymKey, hash);
            boolean verifySignature = security.verifyMessageSignature(clientPublicKey, hashDecrypted, msgDecrypted);

            System.out.println("Msg: " + new String(msgDecrypted));
            System.out.println("Msg is verified:" + verifySignature);
            System.out.println("Sending message to peers");

            if (verifySignature)
                server.handle(this, msgDecrypted);
            else {
                System.out.println("Error! Possible attack. Shutdown client.");
                this.stop();
            }

            // Force key exchange every 10 seconds
            long totalTime = (System.currentTimeMillis() / 1000) - startTime;
            System.out.println("Time:" + totalTime);

            if( totalTime > 30)
            {
                System.out.println("Renew lease");
                startTime = System.currentTimeMillis() / 1000;
                secureConnectionEstablished = false;
            }

        }
    }

    // Opens thread
    public void open() throws IOException
    {  
        streamIn = new DataInputStream(new 
                        BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
    }
    
    // Closes thread
    public void close() throws IOException
    {  
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
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

    public PrivateKey getServerPrivateKey() {
        return serverPrivateKey;
    }

    public SecretKey getServerSymKey() {
        return serverSymKey;
    }


}

