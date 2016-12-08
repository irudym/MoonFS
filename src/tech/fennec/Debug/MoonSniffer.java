package tech.fennec.Debug;

import tech.fennec.Utils.MoonLog;
import tech.fennec.Protocol.SMB;
import tech.fennec.Protocol.SMBCommand;
import tech.fennec.Protocol.SMBProtocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Created by Igor Rudym on 16-Nov-16.
 * The purpose of this class is sniffering real SMB protocol communication to debug
 * moonFS development
 */
public class MoonSniffer {

    protected Socket clientSocket;
    protected int portNum;
    protected static boolean serverContinue = true;
    protected SMBProtocol smbProtocol;
    String address;

    public MoonSniffer(String adr, int port) {
        address = adr;
        portNum = port;
        smbProtocol = new SMBProtocol();
    }

    public byte[] sendData(byte[] buffer, int size) {
        byte[] result = null;
        try {
            byte[] server_buffer = new byte[255];
            MoonLog.debug("Sniffer: create connection to real SMB server: " + address);
            Socket socket = new Socket(address, portNum);
            socket.setTcpNoDelay(true);

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            MoonLog.debug("Sniffer: send data to real SMB server");
            MoonLog.debug("Sniffer: " + MoonLog.toHexString(buffer, size));
            out.write(buffer, 0, size);

            out.flush();
            in.read(server_buffer, 0, 4);
            MoonLog.debug("Sniffer - get data from SMB server: " + MoonLog.toHexString(server_buffer, 4));

            int packet_size = 0;
            byte[] buffer2 = new byte[512];
            byte[] buffer3;
            try {
                packet_size = smbProtocol.getTCPHeader(server_buffer).length;

                MoonLog.debug("Sniffer: Packet size: " + packet_size);
                in.read(buffer2, 0, packet_size);
                MoonLog.debug("Sniffer: " + MoonLog.toHexString(buffer2, packet_size));

                SMB.SMB2_HeaderSync smb2Header = smbProtocol.getSMB2Header(Arrays.copyOfRange(buffer2, 0, 64));
                MoonLog.debug("SMBHeader:\n" + smb2Header);

                buffer3 = new byte[packet_size - smb2Header.getPacketSize()];
                System.arraycopy(buffer2,smb2Header.getPacketSize(), buffer3, 0, buffer3.length);

                SMBCommand.SMB_Parameters_Negotiate smbParameters = smbProtocol.getSMBParametersNegotiateHeader(buffer3);
                MoonLog.debug("SMBNegotiateParameters:\n" + smbParameters);

                buffer2 = new byte[packet_size - smb2Header.getPacketSize() - smbParameters.getPacketSize()];
                int offset = smbParameters.getPacketSize();
                System.arraycopy(buffer3,offset, buffer2, 0, buffer2.length);

                SMBCommand.SMB_Data data = smbProtocol.getSMBData(buffer2);
                MoonLog.debug("SMBData:\n" + smbParameters);

                //result = new byte[4 + packet_size];
                //System.arraycopy(server_buffer,0,result, 0, 4);
                //System.arraycopy(buffer2, 0, result, 4, packet_size);

                out.close();
                in.close();
                socket.close();
            } catch (Exception e) {
                MoonLog.error(e.getMessage());
            }
        } catch (IOException  e) {
            MoonLog.error(e.getMessage());
        }
        return result;
    }

    public void accept(Socket clientSocket) {
        MoonLog.info("Sniffer: Accepting connection from remote host: " + clientSocket.toString());
        try {
            clientSocket.setSoLinger(false, 0);
            clientSocket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            byte[] buffer = new byte[512];
            byte[] buffer2 = new byte[512];
            byte[] outbuffer;
            int read;
            boolean session = true;

            smbProtocol = new SMBProtocol();

            while(session) {
                while (in.available() == 0) ;

                //Read first 4 bytes with packet size

                in.read(buffer, 0, 4);
                MoonLog.debug("Sniffer: " + MoonLog.toHexString(buffer, 4));

                int packet_size = 0;
                byte[] response;
                try {
                    packet_size = smbProtocol.getTCPHeader(buffer).length;
                    MoonLog.debug("Sniffer: Packet size: " + packet_size);

                    in.read(buffer2, 0, packet_size);
                    MoonLog.debug("Sniffer: " + MoonLog.toHexString(buffer2, packet_size));

                    outbuffer = new byte[4 + packet_size];
                    System.arraycopy(buffer,0,outbuffer, 0, 4);
                    System.arraycopy(buffer2, 0, outbuffer, 4, packet_size);
                    byte[] res = sendData(outbuffer, packet_size+4);
                    if(res!=null) out.write(res, 0, res.length);

                } catch (Exception e) {
                    MoonLog.error(e.getMessage());
                }
            }

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

    public void createServer(int portNum) {
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(portNum, 100);
            MoonLog.info("Start Sniffer on port: " + portNum);
            try {
                while (serverContinue)
                {

                    serverSocket.setSoTimeout(100000);
                    MoonLog.info("\tWaiting for Connection at port:" + portNum);
                    try {
                        accept(serverSocket.accept());
                    }
                    catch (SocketTimeoutException ste)
                    {
                        MoonLog.info("Timeout Occurred");
                    }
                }
            }
            catch (IOException e)
            {
                MoonLog.error("Accept failed.");
                System.exit(1);
            }
        }
        catch (IOException e)
        {
            MoonLog.error("Could not listen on port: " + portNum);
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


    public byte[] testSeq(String filename) {
        int bytes = 0;
        byte[] buffer = new byte[512];
        byte[] result;
        try {
            Scanner scanner = new Scanner(new File(filename));

            while (scanner.hasNext()) {
                buffer[bytes++] = (byte)(Long.parseLong(scanner.next(), 16) & 0xff);
            }
        } catch (IOException e) {
            MoonLog.error(e.getMessage());
        }
        MoonLog.info("BYTES readed: " + bytes);
        result = new byte[bytes];
        System.arraycopy(buffer,0, result, 0, bytes);
        return result;
    }

    public void start(int port) {
        //start server
        createServer(port);
    }
}
