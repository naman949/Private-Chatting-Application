import java.io.*;
import java.net.*;
import java.util.*;

class Server
{
	public static ArrayList<ClientConnections> connections;

	public static void main(String... args) 
	{
		try{
			ServerSocket ss = new ServerSocket(5000);
			connections = new ArrayList<ClientConnections>();
			while(true)
			{
				Socket s = ss.accept();
				Register r = new Register(s, connections);
				r.start();
			}
		}catch(Exception e)
		{System.out.println(e);}
	}
}

class Register extends Thread
{
	ArrayList<ClientConnections> connections;
	Socket s;

	Register(Socket s, ArrayList<ClientConnections> connections)
	{
		this.s = s;
		this.connections = connections;
	}

	public boolean valid(String s)
	{
		return s!=null && s.matches("^[a-zA-Z0-9]*$");
	}

	public void run()
	{
		try{
			DataInputStream dis = new DataInputStream(s.getInputStream());
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			boolean registered = false;
			while(!registered)
			{
				String request = dis.readUTF();
				if(request.length()<16)
				{
					dos.writeUTF("ERROR 101 No user registered\n\n");
					dos.flush();
				}
				else if(request.substring(0,15).equals("REGISTER TOSEND"))
				{
					String name = request.substring(16,request.length()-2);
					if(valid(name))
					{
						ListIterator it = connections.listIterator();
						boolean sameName = false;
						while(it.hasNext())
						{
							ClientConnections client = (ClientConnections)it.next();
							if(client.name.equals(name))
								sameName = true;
						}
						if(!sameName)
						{
							ClientConnections client = new ClientConnections(s, name, connections);
							connections.add(client);
							registered=true;
							dos.writeUTF("REGISTERED TOSEND " + name + "\n\n");
							dos.flush();
						}
						else
						{
							dos.writeUTF("ERROR 200 Username already registered\n\n");
							dos.flush();
						}
					}
					else
					{
						dos.writeUTF("ERROR 100 Malformed username\n\n");
						dos.flush();
					}
				}
				else if(request.substring(0,15).equals("REGISTER TORECV"))
				{
					String name = request.substring(16,request.length()-2);
					ListIterator it = connections.listIterator();
					for(ClientConnections client : connections)
					{
						if(client.name.equals(name))
						{
							client.receivingSocket = s;
							dos.writeUTF("REGISTERED TORECV " + name + "\n\n");
							dos.flush();
							String key = dis.readUTF();
							if(key.equals("NO ENCRYPTION\n\n"))
							{
								client.key = null;
								dos.writeUTF("OK\n\n");
							}
							else if(key.substring(0,18).equals("REGISTER PUBLICKEY"))
							{
								String public_key = key.substring(19,key.length()-2);
								client.key = public_key;
								dos.writeUTF("REGISTERED PUBLICKEY\n\n");
							}
							else
								dos.writeUTF("ERROR 201 Unknown Request");
							dos.flush();
							client.start();
							registered = true;
							break;
						}
					}
					if(!registered)
						System.out.println("Some Error Occured 2");
				}
				else
				{
					dos.writeUTF("ERROR 101 No user registered\n\n");
					dos.flush();
				}
			}
		}catch(Exception e)
		{
			System.out.println(e + " : Error during registration");
		}
	}
}

class ClientConnections extends Thread
{
	ClientConnections c;
	Socket sendingSocket;
	Socket receivingSocket;
	String name;
	String key;
	ArrayList<ClientConnections> connections;

	ClientConnections(Socket sendingSocket, String name, ArrayList<ClientConnections> connections)
	{
		this.sendingSocket = sendingSocket;
		this.receivingSocket = null;
		this.name = name;
		this.connections = connections;
	}

	public void run()
	{
		try{
			DataInputStream dis = new DataInputStream(sendingSocket.getInputStream());
			DataOutputStream sdos = new DataOutputStream(sendingSocket.getOutputStream());
			while(true)
			{
				String msg = dis.readUTF();
				if(msg.substring(0,8).equals("FETCHKEY"))
				{
					String of = msg.substring(9,msg.length()-2);
					boolean foundName = false;
					for(ClientConnections c : connections)
					{
						if(c.name.equals(of))
						{
							sdos.writeUTF(c.key);
							sdos.flush();
							foundName = true;
							break;
						}
					}
					if(!foundName)
					{
						sdos.writeUTF("Could not find name");
						sdos.flush();
					}
				}
				else
				{
					String[] parts = msg.split("\n");
					if(parts.length == 4)
					{
						if(parts[0].substring(0,4).equals("SEND") 
							&& parts[1].substring(0,15).equals("Content-length:") 
							&& Integer.parseInt(parts[1].substring(16)) == parts[3].length()
							&& parts[2].equals(""))
						{
							String to = parts[0].substring(5);
							boolean foundClient = false;
							for(ClientConnections client : connections)
							{
								if(client.name.equals(to))
								{
									DataOutputStream rdos = new DataOutputStream(client.receivingSocket.getOutputStream());
									rdos.writeUTF("FORWARD " + name + "\n" + parts[1] + "\n\n" + parts[3]);
									rdos.flush();
									DataInputStream rdis = new DataInputStream(client.receivingSocket.getInputStream());
									String reply = rdis.readUTF();
									if(reply.equals("RECEIVED " + name + "\n\n"))
									{
										sdos.writeUTF("SENT " + to + "\n\n");
									}
									else if(reply.substring(0,8).equals("FETCHKEY"))
									{
										rdos.writeUTF(key);
										rdos.flush();
										reply = rdis.readUTF();
										if(reply.equals("RECEIVED " + name + "\n\n"))
										{
											sdos.writeUTF("SENT " + to + "\n\n");
										}
										else
											sdos.writeUTF("ERROR 102 Unable to send\n\n");
									}
									else
									{
										sdos.writeUTF("ERROR 102 Unable to send\n\n");
									}
									sdos.flush();
									foundClient = true;
								}
							}
							if(!foundClient)
							{
								sdos.writeUTF("ERROR 102 Unable to send\n\n");
								sdos.flush();
							}
						}
						else
						{
							sdos.writeUTF("ERROR 103 Header incomplete\n\n");
							sdos.flush();
						}
					}
					else
					{
						sdos.writeUTF("ERROR 103 Header incomplete\n");
						sdos.flush();
					}
				}
			}
		}catch(Exception e)
		{
			connections.remove(this);
			System.out.println(name + " disconnected");
		}
	}
}