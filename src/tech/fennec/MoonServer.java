package tech.fennec;

import tech.fennec.Protocol.*;
import tech.fennec.Utils.MoonLog;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;


/**
 * Created by Igor Rudym on 15-Nov-16.
 */
public class MoonServer extends Thread {
    protected Socket clientSocket;
    protected int portNum;
    protected static boolean serverContinue = true;
    protected SMB smbProtocol;

    public MoonServer(int portNum) {
        this.portNum = portNum;
        smbProtocol = new SMB();
    }


    public void accept(Socket clientSocket) {
        MoonLog.info("Accepting connection from remote host: " + clientSocket.toString());
        try {
            clientSocket.setSoLinger(false, 0);
            clientSocket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            byte[] buffer = new byte[512];
            byte[] outbuffer = new byte[512];
            int read;
            boolean session = true;

            while(session) {
                //while (in.available() == 0) ;

                //Read first 4 bytes with packet size

                in.read(buffer, 0, 4);
                MoonLog.debug(MoonLog.toHexString(buffer, 4));

                SMBCommand smbCommand = new SMBCommand();
                int packet_size = 0;
                byte[] response;
                try {
                    packet_size = smbProtocol.getTCPHeader(buffer).length;
                    MoonLog.debug("Packet size: " + packet_size);

                    //read SMB data - header + params
                    in.read(buffer, 0, packet_size);
                    MoonLog.debug(MoonLog.toHexString(buffer, packet_size));

                    response = smbProtocol.responsePacket(smbProtocol.dispatchPacket(buffer, packet_size));
                    MoonLog.debug("MoonFS response: " + MoonLog.toHexString(response));
                    out.write(response, 0, response.length);
                    out.flush();
                    MoonLog.debug("data sent");
                } catch (Exception e) {
                    MoonLog.error(e.getMessage());
                    session = false;
                }
            }

            MoonLog.info("Close all connections");

            out.close();
            in.close();
            clientSocket.close();

        }
        catch (IOException e)
        {
            System.err.println("Problem with Communication Server: " + e.getMessage());
            //System.exit(1);
        }
    }

    public void run() {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(portNum, 100);
            //System.out.println("Connection Socket Created at port: " + portNum);
            System.out.println("Start MoonServer on port: " + portNum);
            try {
                while (serverContinue)
                {

                    serverSocket.setSoTimeout(100000);
                    System.out.println ("\tWaiting for Connection at port:" + portNum);
                    try {
                        accept(serverSocket.accept());
                    }
                    catch (SocketTimeoutException ste)
                    {
                        System.out.println ("Timeout Occurred");
                    }
                }
            }
            catch (IOException e)
            {
                System.err.println("Accept failed.");
                System.exit(1);
            }
        }
        catch (IOException e)
        {
            System.err.println("Could not listen on port: " + portNum);
            System.exit(1);
        }
        finally
        {
            try {
                System.out.println ("Closing Server Connection Socket");
                serverSocket.close();
            }
            catch (IOException e)
            {
                System.err.println("Could not close port: " + portNum);
                System.exit(1);
            }
        }
    }

    //create server as new thread
    public static MoonServer createServer(int portNum) {
        MoonServer server = new MoonServer(portNum);
        server.start();
        return server;
    }

}
