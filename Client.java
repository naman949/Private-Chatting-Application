import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Base64;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

class Client
{
	public static void main(String[] argv)
	{
		if(argv.length != 3)
		{
			System.out.println("Invalid Input Arguments");
		}
		else
		{
			String name = argv[0];
			String ServerIP = argv[1];
			int type = Integer.parseInt(argv[2]);
			Thread senderThread = null;
			Thread receiverThread = null;
			try{
				Socket sendingSocket = new Socket(ServerIP, 5000);
				DataInputStream ssdis = new DataInputStream(sendingSocket.getInputStream());
				DataOutputStream ssdos = new DataOutputStream(sendingSocket.getOutputStream());
				byte[] publicKey = null, privateKey = null;
				String encryptedPublicKey = null;
				MessageDigest md = null;
				if(type>0)
				{
					KeyPair keyPair = CryptographyExample.generateKeyPair();
					publicKey = keyPair.getPublic().getEncoded();
        			privateKey = keyPair.getPrivate().getEncoded();
        			encryptedPublicKey = Base64.getEncoder().encodeToString(publicKey);
        		}
        		if(type>1)
        		{
        			md = MessageDigest.getInstance("SHA-256");
        		}
				boolean nameAccepted = false;
				while(!nameAccepted)
				{
					ssdos.writeUTF("REGISTER TOSEND " + name + "\n\n");
					ssdos.flush();
					String reply = ssdis.readUTF();
					if(reply.equals("REGISTERED TOSEND " + name + "\n\n"))
					{
						System.out.println("Sending Connection Established");
						Sender sender;
						if(type>1)
							sender = new Sender(sendingSocket, name, type, privateKey, md);
						else
							sender = new Sender(sendingSocket, name, type);
						senderThread = new Thread(sender);
						senderThread.start();
						nameAccepted = true;
					}
					else if(reply.equals("ERROR 100 Malformed username\n\n"))
					{
						System.out.println("Username should only contain Alphabets or Numbers. Please enter a different username");
						Scanner scanner = new Scanner(System.in);
						if(scanner.hasNextLine())
							name = scanner.nextLine();
					}
					else if(reply.equals("ERROR 200 Username already registered\n\n"))
					{
						System.out.println("Username already registered. Please Enter a different username.");
						Scanner scanner = new Scanner(System.in);
						if(scanner.hasNextLine())
							name = scanner.nextLine();
					}
					else
					{
						System.out.println(reply + " : error during creation of sending connection");
						System.exit(0);
					}
				}

				Socket receivingSocket = new Socket(ServerIP, 5000);
				DataInputStream rsdis = new DataInputStream(receivingSocket.getInputStream());
				DataOutputStream rsdos = new DataOutputStream(receivingSocket.getOutputStream());
				rsdos.writeUTF("REGISTER TORECV " + name + "\n\n");
				rsdos.flush();
				String reply = rsdis.readUTF();
				if(reply.equals("REGISTERED TORECV " + name + "\n\n"))
				{
					System.out.println("Receiving Connection Established");
					Receiver receiver;
					if(type>0)
					{
						receiver = new Receiver(receivingSocket, privateKey, type, md);
						rsdos.writeUTF("REGISTER PUBLICKEY " + encryptedPublicKey + "\n\n");
						reply = rsdis.readUTF();
						if(reply.equals("REGISTERED PUBLICKEY\n\n"))
							System.out.println("Encryption setup complete");
						else
							System.out.println("Could not setup encryption");
						if(type==2)
							System.out.println("With Signature");
					}
					else
					{
						receiver = new Receiver(receivingSocket, type);
						rsdos.writeUTF("NO ENCRYPTION\n\n");
						rsdos.flush();
						reply = rsdis.readUTF();
						if(reply.equals("OK\n\n"))
							System.out.println("No encryption");
						else
							System.out.println("Some error occured");
					}
					receiverThread = new Thread(receiver);
					receiverThread.start();
				}
				else
				{
					System.out.println(reply + " : error during creation of receiving connection");
					System.exit(0);
				}
				if(senderThread != null)
					senderThread.join();
				if(receiverThread != null)
					receiverThread.join();
				System.out.println("Client Closed!");
			}catch(Exception e)
			{
				System.out.println(e + " : some problem");
			}
		}
	}
}

class Sender implements Runnable
{
	Socket s;
	String name;
	int type;
	byte[] privateKey;
	MessageDigest md;

	Sender(Socket s, String name, int type)
	{
		this.s = s;
		this.name = name;
		this.type = type;
		this.privateKey = null;
		this.md = null;
	}

	Sender(Socket s, String name, int type, byte[] privateKey, MessageDigest md)
	{
		this.s = s;
		this.name = name;
		this.type = type;
		this.privateKey = privateKey;
		this.md = md;
	}

	public static byte[] encryptUsingPrivate(byte[] privateKey, byte[] inputData) throws Exception {        
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(inputData);
        return encryptedBytes;
    }

	public void run()
	{
		try{
			Scanner scanner = new Scanner(System.in);
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			DataInputStream dis = new DataInputStream(s.getInputStream());
			while(scanner.hasNextLine())
			{
				String msg = scanner.nextLine();
				String[] parts = msg.split(" ",2);
				if(parts.length == 2 && msg.charAt(0)=='@')									//verify syntax of input
				{
					String to = parts[0].substring(1);										//extract name to whom the msg is to be sent
					String finalMsg = parts[1];										
					if(to.equals(name))														//do not send message if sending to itself
					{
						System.out.println("Don't be stupid!");
						continue;
					}
					if(type>0)																//check if message needs to be encrypted
					{
						dos.writeUTF("FETCHKEY " + to + "\n\n");
						dos.flush();
						String key = dis.readUTF();
						if(key.equals("Could not find name"))
						{
							System.out.println("Could not send message");
							continue;
						}
						else
						{
							byte[] decryptedKey = Base64.getDecoder().decode(key);
							byte[] encryptedMsg = CryptographyExample.encrypt(decryptedKey, parts[1].getBytes());
							finalMsg = Base64.getEncoder().encodeToString(encryptedMsg);
							if(type>1)														//check if message digest needs to be inserted
							{
								byte[] digest = md.digest(parts[1].getBytes());
								byte[] encryptedDigest = encryptUsingPrivate(privateKey, digest);
								finalMsg = Base64.getEncoder().encodeToString(encryptedDigest) + finalMsg;
							}
						}
					}
					String send = "SEND " + to;
					String content = "Content-length: " + finalMsg.length();
					dos.writeUTF(send + "\n" + content + "\n\n" + finalMsg);
					dos.flush();
					String reply = dis.readUTF();
					if(reply.equals("SENT " + to + "\n\n"))
					{}
					else
						System.out.println("Could not send message");
				}
				else
				{
					System.out.println("The format is not correct. Please type again.");
				}
			}
		}catch(Exception e)
		{
			System.out.println(e + "Sender Connection Closed");
		}
	}
}

class Receiver implements Runnable
{
	Socket s;
	byte[] privateKey;
	int type;
	MessageDigest md;

	Receiver(Socket s, int type)
	{
		this.s = s;
		this.privateKey = null;
		this.type = type;
		this.md = null;
	}

	Receiver(Socket s, byte[] privateKey, int type, MessageDigest md)
	{
		this.s = s;
		this.privateKey = privateKey;
		this.type = type;
		this.md = md;
	}

	public static byte[] decryptUsingPublic(byte[] publicKey, byte[] inputData) throws Exception {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(inputData);
        return decryptedBytes;
    }

	public void run()
	{
		try{
			DataInputStream dis = new DataInputStream(s.getInputStream());
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			while(true)
			{
				String msg = dis.readUTF();
				String[] parts = msg.split("\n");
				if(parts.length == 4)
				{
					if(parts[0].substring(0,7).equals("FORWARD") 
						&& parts[1].substring(0,15).equals("Content-length:") 
						&& Integer.parseInt(parts[1].substring(16)) == parts[3].length()
						&& parts[2].equals(""))
					{
						String from = parts[0].substring(8);
						String data = parts[3];
						String digest = "";
						boolean verified = false;
						if(type>0)
						{
							if(type==2)															//seperate digest and message
							{
								digest = parts[3].substring(0,88);
								parts[3] = parts[3].substring(88);
							}
							byte[] decryptedMsg = Base64.getDecoder().decode(parts[3]);
							data = new String(CryptographyExample.decrypt(privateKey, decryptedMsg));
							if(type==2)															//verify digest
							{
								byte[] decodedDigest = Base64.getDecoder().decode(digest);
								dos.writeUTF("FETCHKEY " + from + "\n\n");
								dos.flush();
								String key = dis.readUTF();
								byte[] decryptedKey = Base64.getDecoder().decode(key);
								byte[] decryptedDigest = decryptUsingPublic(decryptedKey, decodedDigest);
								byte[] myDigest = md.digest(data.getBytes());
								if(Arrays.equals(myDigest, decryptedDigest))
									verified = true;
								else
								{
									dos.writeUTF("ERROR 202 Signature not verified");
									dos.flush();
								}
							}
						}
						if(verified || type<2)
						{
							System.out.println("#" + from + " " + data);
							dos.writeUTF("RECEIVED " + from + "\n\n");
							dos.flush();
						}
					}
					else
					{
						dos.writeUTF("ERROR 103 Header incomplete\n");
						dos.flush();
					}
				}
				else
				{
					dos.writeUTF("ERROR 103 Header incomplete\n\n");
					dos.flush();
				}
			}
		}catch(Exception e)
		{
			System.out.println("Receiver Connection Closed");
		}
	}
}