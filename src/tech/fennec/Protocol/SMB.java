package tech.fennec.Protocol;

import org.ietf.jgss.*;
import tech.fennec.Utils.MSDType;
import tech.fennec.Utils.MoonLog;
import tech.fennec.Utils.Buffer;

import tech.fennec.Protocol.Commands.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Calendar;

/**
 * Created by irudym on 15-Nov-16.
 */
public class SMB {

    protected short currentCommand;


    protected String ServerGuid = "MoonFS";


    GSSContext GSScontext;
    byte[] GSStoken;


    public SMB() {

        //init GSS context
        GSSManager manager = GSSManager.getInstance();
        try {
            Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
            GSSName serverName = manager.createName(ServerGuid+"@fennec.tech", GSSName.NT_HOSTBASED_SERVICE, spnegoOid);
            GSScontext = manager.createContext(serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME);

            //generate security token
            GSStoken = new byte[0];
            GSStoken = GSScontext.initSecContext(GSStoken, 0, GSStoken.length);
        } catch (GSSException e) {
            MoonLog.error("Error while GSS context initializing: " + e.getMessage());
            MoonLog.error( "GSSException major: " + e.getMajorString() );
            MoonLog.error( "GSSException minor: " + e.getMinorString() );
        }
    }


    //Capabilities
    public static int SMB2_GLOBAL_CAP_DFS = 0x00000001;
    public static int SMB2_GLOBAL_CAP_LEASING = 0x00000002;
    public static int SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004;
    public static int SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008;
    public static int SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010;
    public static int SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020;
    public static int SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040;              //When set, indicates that the server supports encryption. This flag is valid for the SMB 3.0 and 3.0.2 dialects.

    //Security modes
    public static short SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;
    public static short SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002;

    /*
    When using Direct TCP as the SMB transport, the implementer MUST prepend a 4-byte Direct TCP
    transport packet header to each SMB message. This transport header MUST be formatted as a byte
    of zero (8 zero bits) followed by 3 bytes that indicate the length of the SMB message that is
    encapsulated. The body of the SMB packet follows as a variable-length payload. A Direct TCP transport
    packet has the following structure (in network byte order).
    Zero (1 byte): The first byte of the Direct TCP transport packet header MUST be zero (0x00).

    Stream Protocol Length (3 bytes): The length, in bytes, of the SMB message. This length is
        formatted as a 3-byte integer in network byte order. The length field does not include the 4-byte
        Direct TCP transport header; rather, it is only the length of the enclosed SMB message. For SMB
        messages, if this value exceeds 0x1FFFF, the server SHOULD<4> disconnect the connection.

    SMB Message (variable): The body of the SMB packet.
    */

    //The header size is 4 bytes
    public class TCP_Header extends SMBPacket {
        public byte zeros;
        public int length; //should be size of 3;

        public void fillStructure(byte[] buffer) throws Exception {
            zeros = buffer[0];
            length = (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3] & 0xff);
        }

        public byte[] response() {
            byte[] res = new byte[4];
            res[0] = 0;
            res[1] = (byte)((length >> 16) & 0xff);
            res[2] = (byte)((length >> 8) & 0xff);
            res[3] = (byte)(length & 0xff);

            return res;
        }

        public int getPacketSize() {
            return 4;
        }
    }

    /*
    SMB_Header
    {
    UCHAR Protocol[4];
    UCHAR Command;
    SMB_ERROR Status;
    UCHAR Flags;
    USHORT Flags2;
    USHORT PIDHigh;
    UCHAR SecurityFeatures[8];
    USHORT Reserved;
    USHORT TID;
    USHORT PIDLow;
    USHORT UID;
    USHORT MID;
    }
    */
    enum SMB_ERROR {};

    //overall size of SMB_Header is 32 bytes
    public class  SMB_Header extends SMBPacket {
        //public byte[] Protocol = new byte[4]; //should be size of 4
        public int Protocol;  //should be size of 4
        public byte Command;
        public int Status;
        public byte Flags;
        public int Flags2;
        public int PIDHigh;
        byte[] SecurityFeatures = new byte[8]; //should be size of 8
        int Reserved;
        int TID;
        int PIDLow;
        int UID;
        int MID;

        public String toString() {
            String res = "\t-------------------------" +
                        "\n\t| Protocol | " + MoonLog.hex(Protocol) + " |"+
                        "\n\t| Command  | " + MoonLog.hex(Command) + "         |"+
                        "\n\t| Status   | " + MoonLog.hex(Status) + " |"+
                        "\n\t| Flags    | " + MoonLog.hex(Flags) + "         |"+
                        "\n\t| Flags2   | " + MoonLog.hex(Flags2) + " |"+
                        "\n\t| PIDHigh  | " + MoonLog.hex(PIDHigh) + " |"+
                        "\n\t| TID      | " + MoonLog.hex(TID) + " |"+
                        "\n\t| PIDLow   | " + MoonLog.hex(PIDLow) + " |"+
                        "\n\t| UID      | " + MoonLog.hex(UID) + " |"+
                        "\n\t| MID      | " + MoonLog.hex(MID) + " |"+
                    "\n\t-------------------------";
            return res;
        }

        public void fillStructure(byte[] buffer) throws Exception {
            Protocol = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3] & 0xff);
            Command = buffer[4];
            Status = (buffer[5] << 24) | (buffer[6] << 16) | (buffer[7] << 8) | (buffer[8] & 0xff);
            Flags = buffer[9];
            Flags2 = (buffer[10] << 8) | (buffer[11] & 0xff);
            PIDHigh = (buffer[12] << 8) | (buffer[13] & 0xff);
            System.arraycopy(buffer, 14, SecurityFeatures, 0, 8);
            Reserved = (buffer[22] << 8) | (buffer[23] & 0xff);
            TID = (buffer[24] << 8) | (buffer[25] & 0xff);
            PIDLow = (buffer[26] << 8) | (buffer[27] & 0xff);
            UID = (buffer[28] << 8) | (buffer[29] & 0xff);
            MID = (buffer[30] << 8) | (buffer[31] & 0xff);
        }

        public byte[] response() {
            byte[] res = new byte[32];
            res[0] = (byte)0xff; res[1] = 0x53; res[2] = 0x4d; res[3] = 0x42;
            res[4] = Command;
            //TODO: need to fill all fields
            return res;
        }

        public int getPacketSize() {
            return 32;
        }
    }

    //SMB2-3 protocol implementation
    //Flag
    public static int SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;
    public static int SMB2_FLAGS_ASYNC_COMMAND = 0x00000002;
    public static int SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004;
    public static int SMB2_FLAGS_SIGNED = 0x00000008;
    public static int SMB2_FLAGS_PRIORITY_MASK = 0x00000070;
    public static int SMB2_FLAGS_DFS_OPERATIONS = 0x10000000;
    public static int SMB2_FLAGS_REPLAY_OPERATION = 0x20000000;

    public static int getSMBHeaderSize() {
        return 32;
    }

    public class SMB2_HeaderSync extends SMBPacket {
        public int Protocol = 0xfe534d42;//4 bytes
        //TODO: Need to change to short type, in addition to that all 2 bytes values as well
        public short StructureSize = 64;   //2 bytes MUST be 64
        public short CreditCharge;  //2 bytes
        public int ChannelSequence; //4 bytes
        public short Command;       //2 bytes
        public short Credit;        //2 bytes
        public int Flag;            //4 bytes
        public int NextCommand;     //4 bytes
        public byte[] MessageId = null;    //8 bytes
        public int Reserved;        //4 bytes
        public int TreeId;          //4 bytes
        public byte[] SessionId = null;    //8 bytes
        public byte[] Signature = null;    //16 bytes

    public int getPacketSize() {
        return StructureSize;
    }

    public byte[] response() {
        Buffer buffer = new Buffer(StructureSize);

        buffer.bigEndian().putLong(Protocol);
        buffer.putShort(StructureSize);
        buffer.putShort(CreditCharge);
        buffer.putLong(ChannelSequence);
        buffer.putShort(Command);
        buffer.putShort(Credit);
        buffer.putLong(Flag);
        buffer.putLong(NextCommand);

        if(MessageId == null) MessageId = new byte[8]; //create zero filled array
        buffer.putArray(MessageId);
        buffer.putLong(Reserved);
        buffer.putLong(TreeId);

        if(SessionId == null) SessionId = new byte[8];
        buffer.putArray(SessionId);

        if(Signature == null) Signature = new byte[16];
        buffer.putArray(Signature);

        return buffer.getBuffer();
    }

    public void fillStructure(byte[] buffer) throws Exception {
        Buffer dataBuf = new Buffer(buffer);

        Protocol = dataBuf.bigEndian().getLong();

        StructureSize = dataBuf.getShort();
        CreditCharge = dataBuf.getShort();
        ChannelSequence = dataBuf.getLong();
        Command = dataBuf.getShort();
        Credit = dataBuf.getShort();
        Flag = dataBuf.getLong();
        NextCommand = dataBuf.getLong();
        MessageId = dataBuf.getArray(8);
        Reserved = dataBuf.getLong();
        TreeId = dataBuf.getLong();
        SessionId = dataBuf.getArray(8);
        Signature = dataBuf.getArray(16);
    }

    public String toString() {
        return "\t--------------------------------" +
                "\n\t| Protocol        | " + MoonLog.hex(Protocol) + " |"+
                "\n\t| StructureSize   | " + MoonLog.hex(StructureSize) + " |"+
                "\n\t| CreditCharge    | " + MoonLog.hex(CreditCharge) + " |"+
                "\n\t| ChannelSequence | " + MoonLog.hex(ChannelSequence) + " |"+
                "\n\t| Command         | " + MoonLog.hex(Command) + " |"+
                "\n\t| Credit          | " + MoonLog.hex(Credit) + " |"+
                "\n\t| Flag            | " + MoonLog.hex(Flag) + " |"+
                "\n\t| NextCommand     | " + MoonLog.hex(NextCommand) + " |"+
                "\n\t| MessageId       | " + MoonLog.toHexString(MessageId) + " |"+
                "\n\t| Reserved        | " + MoonLog.hex(Reserved) + " |"+
                "\n\t| TreeId          | " + MoonLog.hex(TreeId) + " |"+
                "\n\t| SessionId       | " + MoonLog.toHexString(SessionId) + " |"+
                "\n\t| Signature       | " + MoonLog.toHexString(Signature) + " |"+
                "\n\t--------------------------------";
    }
}


    public SMB2_HeaderSync getSMB2SyncHeader(byte[] buffer) throws Exception {
        if(buffer == null) throw new Exception("cannot get SMB2 header from null buffer");
        SMB2_HeaderSync header = new SMB2_HeaderSync();
        header.fillStructure(buffer);
        if(header.Protocol != 0xfe534d42) throw new Exception("wrong SMB2 Protocol identifier, MUST be '0xFE', 'S', 'M', 'B'");
        return header;
    }

    public int getSMB2HeaderSize() {
        return 64;
    }


    public TCP_Header getTCPHeader(byte[] buffer) throws Exception {
        if(buffer == null) throw new Exception("cannot get TCP header from null buffer");
        TCP_Header header = new TCP_Header();

        header.fillStructure(buffer);
        if(header.zeros!=0) {
            //MoonLog.error("the first byte in the TCP header should be filled with 0");
            throw new Exception("the first byte in the TCP header should be filled with 0");
        }
        return header;
    }

    public SMB_Header getSMBHeader(byte[] buffer) throws Exception {
        SMB_Header header = new SMB_Header();
        header.fillStructure(buffer);
        //check if Protocol is 0xff'S''M''B' = 0xff534d42
        if(header.Protocol != 0xff534d42 && header.Protocol != 0xfe534d42) {
            throw new Exception("the protocol MUST contain the 4-byte literal string '0xFF', 'S', 'M', 'B'");
        }
        return header;
    }

    //DEPRECATED
    public byte[] responsePacket1(byte[] data_buffer) {
        TCP_Header tcpHeader = new TCP_Header();
        SMB_Header smbHeader =new SMB_Header();

        tcpHeader.length = data_buffer.length + smbHeader.getPacketSize();
        byte[] tcpRes = tcpHeader.response();
        byte[] smbRes = smbHeader.response();

        //construct response data packet
        byte[] response = new byte[tcpRes.length + smbRes.length + data_buffer.length];
        System.arraycopy(tcpRes, 0, response, 0, tcpRes.length);
        System.arraycopy(smbRes, 0, response, tcpRes.length, smbRes.length);
        System.arraycopy(data_buffer, 0, response, tcpRes.length + smbRes.length, data_buffer.length);
        return response;
    }

    /**
     * Create response packet for SMB2 protocol
     * @param data_buffer  - byte array which contains a SMB2 header and commnad response data
     * @return byte array which contains all necessary header and response data
     */
    public byte[] responsePacket(byte[] data_buffer) {
        TCP_Header tcpHeader = new TCP_Header();


        //fill TCP header
        tcpHeader.length = data_buffer.length;
        byte[] tcpResp = tcpHeader.response();

        //construct response data
        byte[] response = new byte[tcpResp.length + data_buffer.length];
        System.arraycopy(tcpResp, 0, response, 0, tcpResp.length);
        System.arraycopy(data_buffer, 0, response, tcpResp.length, data_buffer.length);
        return response;
    }


    /**
     * analyze packet and run appropriate command for protocol version 2 and later
     * @param buffer - data buffer with parameters
     * @param packet_size - size of the packet
     * @return
     */
    public byte[] dispatchPacket(byte[] buffer, int packet_size) {
        SMBPacket smbHeader = null;
        SMB2_HeaderSync smbResp = new SMB2_HeaderSync();

        int version = 1;
        byte[] command_result = null;

        try {
            if(buffer[0] == (byte)0xff) {
                smbHeader = new SMB_Header();
            } else if(buffer[0] == (byte)0xfe) {//version 2
                smbHeader = new SMB2_HeaderSync();
                version = 2;
            } else throw new Exception("Unknown protocol type: " + MoonLog.hex(buffer[0]));

            smbHeader.fillStructure(buffer);
            int data_size = packet_size - smbHeader.getPacketSize();
            byte[] data_buffer = new byte[data_size];
            System.arraycopy(buffer, smbHeader.getPacketSize(), data_buffer, 0, data_size);
            if(version == 1) {
                SMB_Header header = (SMB_Header)smbHeader;
                smbResp.Command = header.Command;
                if(header.Command == SMBCommand.SMB_COM_NEGOTIATE) {
                    MoonLog.info("SMB v1 Negotiate request");
                    command_result = runComNegotiateSMB1(data_buffer);
                }
            } else {
                SMB2_HeaderSync header = (SMB2_HeaderSync)smbHeader;
                smbResp.Command = header.Command;
                if(header.Command == SMBCommand.SMB2_NEGOTIATE) {
                    MoonLog.info("SMB v2 Negotiate request");
                    command_result = runComNegotiate(data_buffer);
                }
            }

        } catch (Exception e) {
            MoonLog.error("dispatchPacket:: " + e.getMessage());
        }
        if(command_result!=null) {
            //construct response header
            smbResp.Credit = 1;
            smbResp.Flag = SMB2_FLAGS_SERVER_TO_REDIR;  //set response header type

            byte[] smbHeaderBuffer = smbResp.response();

            byte[] res = new byte[smbResp.getPacketSize() + command_result.length];
            System.arraycopy(smbHeaderBuffer, 0, res, 0, smbHeaderBuffer.length);
            System.arraycopy(command_result, 0, res, smbHeaderBuffer.length, command_result.length);
            return res;
        }
        return null;
    }


    /*
     * Negotiat protocol request/response
     */

    protected SMB2_NegotiateResponse getNegotiationResponse() {
        SMB2_NegotiateResponse negotiateResponse = new SMB2_NegotiateResponse();
        negotiateResponse.StructureSize = 0x41; //The server MUST set this field to 65, indicating the size of the response structure, not including the header.
        negotiateResponse.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
        negotiateResponse.DialectRevision = 0x02ff;
        negotiateResponse.NegotiateContextCount_Reserved = 0x0;
        negotiateResponse.ServerGuid = new byte[16];
        byte[] s_guid = Buffer.toArray(ServerGuid);
        System.arraycopy(s_guid, 0, negotiateResponse.ServerGuid,0, s_guid.length);
        negotiateResponse.Capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LARGE_MTU;//0x05;
        negotiateResponse.MaxTransactSize = 0x800000;
        negotiateResponse.MaxReadSize = 0x800000;
        negotiateResponse.MaxWriteSize = 0x800000;
        //TODO: Somethoing
        negotiateResponse.SystemTime = Buffer.longToArray(MSDType.millisToFiletime(Calendar.getInstance().get(Calendar.MILLISECOND)));
        negotiateResponse.ServerStartTime = new byte[8];
        negotiateResponse.SecurityBufferOffset = 0x80;

        //get a client proposed security mechanism
        //negotiateResponse.SecurityBufferLength = 74;
        //negotiateResponse.Buffer_variable = new byte[74];
        negotiateResponse.NegotiateContextOffset_Reserved2 = 0;
        return negotiateResponse;
    }

    public byte[] runComNegotiateSMB1(byte[] buffer) throws Exception {

        MoonLog.info("run SMB_COM_NEGOTIATE command");
        MoonLog.debug(MoonLog.toHexString(buffer));

        if(buffer[0] != 0) {
            throw new Exception("The field SMB_Parameters should be 0x00. No parameters are sent by this message.");
        }
        //buffer[1] and buffer[2] - ByteCount
        if(buffer[3] != 0x02) {
            throw new Exception("This field MUST be 0x02. This is a buffer format indicator that identifies the next field as a null-terminated array of characters.");
        }
        int pos = 4, c = 0;
        byte[] dialect = new byte[128];
        while(pos < buffer.length) {
            dialect[c++] = buffer[pos];
            if(buffer[pos] == 0) {
                MoonLog.debug(MoonLog.toASCIIString(dialect, c));
                c = 0;
            }
            pos++;
        }

        //return SMB2 negotiation response
        SMB2_NegotiateResponse negotiateResponse = getNegotiationResponse();
        return negotiateResponse.response();
    }

    public byte[] runComNegotiate(byte[] buffer) {
        SMB2_NegotiateRequest negotiateRequest;
        try {
            negotiateRequest = new SMB2_NegotiateRequest(buffer);
            MoonLog.debug("Request: \n" + negotiateRequest);
        } catch (Exception e) {
            MoonLog.error("runComNegotiate: " + e.getMessage());
        }

        SMB2_NegotiateResponse negotiateResponse = getNegotiationResponse();
        return negotiateResponse.response();
    }
}
